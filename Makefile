# lab-ace Makefile — host 构建 + 验证
#
#   make          构建全部（host gcc，x86_64）
#   make bin      仅构建（输出到 bin/host/）
#   make test     跑 host 验证：clean / cave / brk / split 四场景
#   make clean
#
# 真机（Android/NDK）构建见 ../scripts/build-lab-ace.sh

CC      ?= gcc
CFLAGS  ?= -O0 -g -Wall -Wextra -std=gnu11 -pthread -D_GNU_SOURCE
BIN     := bin/host
SRCS    := labtarget.c det_selfcrc.c det_crossread.c det_pagemap.c \
           det_timing.c det_faultcount.c det_selfmod.c det_kallsyms.c \
           det_kcore.c det_dmesg.c det_sysfs.c det_elfhash.c \
           det_trampoline.c det_callstack.c det_hwbp.c det_procscan.c \
           det_perf.c det_diff.c det_linkmap.c ace.c
TARGETS := $(SRCS:.c=)

all: bin

bin:
	@mkdir -p $(BIN)
	@for f in $(TARGETS); do \
		echo "  CC  $$f"; \
		$(CC) $(CFLAGS) -o $(BIN)/$$f $$f.c || exit 1; \
	done
	@$(CC) $(CFLAGS) -I. -o $(BIN)/sim_hook host/sim_hook.c || exit 1
	@echo "built -> $(BIN)/"

test: bin
	@PATH="$(abspath $(BIN)):$$PATH" sh host/test_ace.sh

clean:
	rm -rf bin

.PHONY: all bin test clean
