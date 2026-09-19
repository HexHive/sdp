# FZY: Build the arbitrary read/write proof of concepts.
#
# The PoCs are plain libc user space programs that talk to /dev/arb_rw, so they
# are built natively inside the QEMU RISC-V guest, not as part of the kernel
# tree and not on the host.
#
#   make                  # build every PoC
#   make cred_poc         # build a single PoC
#   make STATIC=1         # link statically
#   make clean

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -g
LDFLAGS ?=

ifeq ($(STATIC),1)
LDFLAGS += -static
endif

# Every .c file in this directory is a self contained PoC; test/ is a separate
# scratch area and is deliberately left out.
SRCS := $(wildcard *.c)
BINS := $(SRCS:.c=)

.PHONY: all clean list

all: $(BINS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

list:
	@printf '%s\n' $(BINS)

clean:
	$(RM) $(BINS)
