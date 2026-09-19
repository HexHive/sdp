## SDP: Sensitive Data Protection

### 1 Overview
#### 1.1 Paper
SDP introduces a unified solution to protect sensitive data against both data-only attacks and control-flow hijacking.
We propose to randomly allocate sensitive data and enforce read and write protection on sensitive pointers through pointer-type-based compartmentalization, which simplifies the overall system design and reduces overhead.
We prototype SDP by extending the RISC-V ISA, evaluate its security guarantees by protecting 16 commonly attacked security-sensitive fields in the Linux kernel, and show its negligible performance impact with a set of micro (LMbench) and macro (Phoronix) benchmarks.
The results demonstrate that SDP provides an effective and practical solution for sensitive data protection.

#### 1.2 Artifact
This artifact includes the full source code of SDP's prototype, namely:
- An SDP emulator (Paper §6.1) that functionally emulates SDP instructions.
- An SDP compiler (Paper §6.3.2) that instruments SDP instructions for sensitive pointers.
- SDP kernels (Paper §8.1) that protect 16 sensitive data fields and their pointers, return addresses, and function pointers.
- Baseline compiler and kernels (Paper §8.3) that SDP compares against.

It reproduces the security evaluation (Paper §8.2) by running 19 proof-of-concept attacks, each of which succeeds on the unprotected kernel and is stopped by SDP.
The performance evaluation (Paper §8.3) is built here and measured on a SiFive Unmatched board over remote access.

Directory tree:
```
artifact-eval/
├── env.sh                    environments
├── docker/
│   ├── Dockerfile            images: sdp-eval and sdp-build
│   ├── build_image.sh        build images
│   └── new_session.sh        start an evaluation session
├── scripts/
│   ├── fetch_upstream.sh     pull the Linux, LLVM, and QEMU trees SDP branched from
│   ├── build_all.sh          build for the security evaluation
│   ├── build_all_perf.sh     build for the performance evaluation
│   ├── build_llvm.sh         build a compiler (sdp/ori)
│   ├── build_qemu.sh         build the SDP emulator
│   ├── build_kernel.sh       build a security evaluation kernel (ori/sd/ret/fp)
│   └── build_kernel_perf.sh  build a performance evaluation kernel (ori/scs/kcfi/scskcfi/sd/ret/fp/fpifp/sdretfp/cred/pt/credpt/retfp)
├── src/
│   ├── patches/              SDP diffs against upstream
│   └── upstream/             upstream code that SDP branched from
├── security-eval/
│   ├── run_vm.sh             boot one guest
│   ├── run_poc_ori_kernel.py run PoCs on the unprotected kernel
│   ├── run_poc_sdp_kernel.py run PoCs on the SDP kernels
│   └── poc/                  the 19 PoCs
├── performance-eval/
│   ├── lmbench/              our LMbench results, five runs per kernel, and result_parse.py
│   │   └── rawprot/          "Protection fault raw" of the eight kernels whose runs above lack it
│   ├── phoronix/             our Phoronix Test Suite results, one per kernel
│   └── kernels/<kernel>/     what build_all_perf.sh leaves for the board
├── vm/                       guest image, initrd, ssh key
└── workdir/<session>/        per-session overlay, shared folder, logs
```

### 2 Access
#### 2.1 Artifact Source
The artifact is available on [Zenodo](https://doi.org/10.5281/zenodo.22775299) and [GitHub](https://github.com/HexHive/sdp).

#### 2.2 Remote Access
We provide remote access over a private [ZeroTier](https://www.zerotier.com) network to a machine for the security evaluation and to the SiFive Unmatched board for the performance evaluation.
Every `<PLACEHOLDER>` below is given in the `infrastructure_access` item of the submitted `metadata.toml`.

1. Install ZeroTier: `curl -s https://install.zerotier.com | sudo bash`
2. Start the service: `sudo systemctl enable --now zerotier-one`
3. Join the network: `sudo zerotier-cli join <NETWORK_ID>`
4. Log in to https://central.zerotier.com (user `<ZT_USER>`, password `<ZT_PASSWORD>`; if a verification code is required, log in to the email account with the same password) and tick **Auth?** for your device, whose address `sudo zerotier-cli info` prints.
5. Change the ZeroTier password, since ZeroTier Central shows the public IP of every device.
6. Check that `sudo zerotier-cli listnetworks` shows `OK`.
7. Log in to our machine as `ssh reviewer1@<HOST_IP>` or `ssh reviewer2@<HOST_IP>` (password `<SSH_PASSWORD>`), and run the security evaluation there.
8. From that machine, open the board's console with `minicom -D /dev/ttyUSB1` (user `<BOARD_USER>`, password `<BOARD_PASSWORD>`), and run the performance evaluation there.

**Important note**: the SiFive Unmatched board admits one reviewer at a time, so please coordinate with each other on when to run the performance evaluation.

### 3 Dependency
#### 3.1 Hardware Dependency
- **Security evaluation**: can be run on the provided machine (§2), where everything is already built and §4.1 can be skipped.
Building it from source requires an x86_64 Linux machine with Docker, at least 16 GB of RAM, and 30 GB of free disk.
- **Performance evaluation**: requires the SiFive Unmatched board and therefore must be run on the provided machine (§2).

#### 3.2 Software Dependency
- **Remote access**: requires a ZeroTier client and ssh.
- **Building from source**: requires Docker (tested with 29.4).
All other tools are included in the images.

### 4 Setup
On the provided machine (§2), skip §4.1: the artifact is in `~/sdp-ae`, with the images and every binary already built.
`cd ~/sdp-ae` and start at §4.2.

#### 4.1 Installation
From the artifact's root directory:
```bash
docker/build_image.sh                                              # 2 min
IMAGE=sdp-build docker/new_session.sh build scripts/build_all.sh   # 55 min
```
The first command builds two images: `sdp-build`, which compiles the artifact, and `sdp-eval`, which runs the evaluation.
The second command downloads upstream Linux, LLVM, and QEMU (~530 MB), applies `src/patches/`, and builds the SDP compiler (33 min), emulator (1 min), and the 4 security evaluation kernels (5 min each).

#### 4.2 Basic Test
```bash
docker/new_session.sh e1 security-eval/run_poc_sdp_kernel.py cred   # 4 min
```
This boots the SDP kernel and runs one PoC; it should end with `STag Mismatch 1, TTag Mismatch 0, Unblocked 0, skipped 0, not run 0`.

### 5 Evaluation Workflow
#### 5.1 Major Claims
##### C1: Security Evaluation
- **Claim.**
SDP protects sensitive data against both data-only attacks and control-flow hijacking.
It mitigates attacks that overwrite sensitive data, sensitive data pointers, or code pointers (Paper §2), whether the attacker controls plain `load/store` or `ld/sd_sc(d)p` of another type (Paper §7.1).

- **Paper results.**
Paper §8.2, Table 2, Appendix C Table 6.

##### C2: Performance Evaluation
- **Claim.**
SDP's performance overhead is negligible compared with the data-only attack mitigation baseline xMP and the control-flow hijacking mitigation baselines SCS and KCFI.

- **Paper results.**
Paper §8.3, Figures 3–8.

#### 5.2 Experiments
##### E1: Security Evaluation
- **Proposed experiment.**
Run 19 PoCs on the unprotected and SDP kernels and observe the output.

- **Justification.**
The 19 PoCs cover all the attack paths, classified along two axes: *what* each overwrites, and *which* `load/store` the attacker controls.
  - By what they overwrite (Paper §2):
    - **Sensitive data** (11):
      - Payload strings: `core_pattern`, `modprobe_path`.
      - Security-policy flags: `sig_enforce`, `selinux_state`, `aa_g_audit`, `sysctl_unprivileged_bpf_disabled`, `sysctl_io_uring_disabled`, `kptr_restrict`, `panic_on_oops`.
      - Struct fields: `cred`, `mm`.
    - **Direct sensitive pointer** (2):
      - `nsproxy`, `fs`: repoints `task_struct.nsproxy`/`.fs` at `init_nsproxy`/`init_fs`.
    - **Indirect sensitive pointer** (2):
      - `page_table`, `init_mm`: walk `pgd → pud → pmd → pte` from `init_mm.pgd` and flips a kernel code page's leaf PTE from R+X to R+W+X.
    - **Direct code pointer** (3):
      - `return_address`: overwrites a saved return address on the stack.
      - `thread`: overwrites the saved `ra` in `task_struct.thread`.
      - `softirq_action`: overwrites a `softirq_vec[]` handler pointer.
    - **Indirect code pointer** (1):
      - `file_op_privesc`: repoints `file->f_op` at a forged `file_operations` whose `.read` is a `commit_creds(&init_cred)` gadget.
  - By the `load/store` the attacker controls (Paper §7.1):
    - **Plain `load/store`** (17): `modprobe_path`, `cred`, `nsproxy`, `fs`, `page_table`, `init_mm`, `mm`, `thread`, `sig_enforce`, `selinux_state`, `aa_g_audit`, `sysctl_unprivileged_bpf_disabled`, `sysctl_io_uring_disabled`, `kptr_restrict`, `panic_on_oops`, `softirq_action`, `file_op_privesc`.
    - **`ld/sd_sc(d)p`** (2): `core_pattern`, `return_address`.

- **Steps.** (~45 min in total on the provided machine)
  ```bash
  docker/new_session.sh e1
  security-eval/run_poc_ori_kernel.py            # unprotected kernel, ~5 min
  security-eval/run_poc_sdp_kernel.py            # SDP kernels, ~40 min
  ```
  Logs are in `workdir/e1/logs` (`/work/logs` in the container): `run_poc_*.log` has every command and its output, `console_*.log` has each guest's console, including the trap and panic.

- **Expected results.**
  ```
  passed 19, failed 0, skipped 0, not run 0                              # run_poc_ori_kernel.py
  STag Mismatch 17, TTag Mismatch 2, Unblocked 0, skipped 0, not run 0   # run_poc_sdp_kernel.py
  ```
  - On the unprotected kernel, all 19 attacks succeed.
  - On the SDP kernels, all 19 are blocked. The 17 plain `load/store` PoCs hit **STag Mismatch**; `core_pattern` and `return_address` use `ld/sd_sdp` with a wrong TTag and hit **TTag Mismatch**.

##### E2: Performance Evaluation
- **Proposed experiment.**
Run LMbench once on each of the 13 kernels (9 SDP kernels, 4 baseline kernels) on the SiFive Unmatched board.

- **Justification.**
LMbench runs OS and hardware primitives only, so it shows what protecting kernel data costs more directly than applications (Phoronix) do.
However, the board is noisy, and our own five runs per kernel show up to 5% variability (standard deviation) on some primitives, so runs should be repeated.
A proposed experiment must fit in one day, which leaves one round (~9 h) per reviewer; more rounds are encouraged if time permits.
Our original results are in `performance-eval/` for reference: `lmbench/<kernel>/`, five runs each, and `phoronix/<kernel>/`.

- **Steps.**
The 13 kernels are installed on the board.
To rebuild them instead (~3 h), run the following and install `performance-eval/kernels/<kernel>/` on the board.
  ```bash
  IMAGE=sdp-build docker/new_session.sh perf scripts/build_all_perf.sh --prune
  ```
  For each kernel, reboot the board, pick it in the boot menu, then:
  ```bash
  cd ~/lmbench
  tmux
  ./run_tests_stable.sh        # then Ctrl-b c, Ctrl-b d: new window, detach. ~40 min
  ```
  When it is done, `~/lmbench/results/` has a new `sdpboard.<n>`.
  After all the 13 kernels have run, `python3 ~/lmbench/results/result_parse.py` prints the latency and bandwidth of each primitive, one column per kernel.

- **Expected results.**
The results should follow the trend of the LMbench overheads in Paper §8.3, but may show the variability noted above.
