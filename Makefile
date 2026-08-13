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

# ARM64 交叉编译检查（需 aarch64-linux-gnu-gcc；NDK 构建前先本地过一遍，
# 防 det_*.c 的 ARM64 分支语法错误只到 CI 才暴露）
check-arm64:
	@command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || { echo "需要 aarch64-linux-gnu-gcc"; exit 1; }
	@rm -rf .a64check && mkdir .a64check
	@for f in $(TARGETS); do \
		aarch64-linux-gnu-gcc -c -O0 -Wall -std=gnu11 -pthread -I. -o .a64check/$$f.o $$f.c \
			|| { echo "FAIL $$f (ARM64)"; rm -rf .a64check; exit 1; }; \
		echo "OK $$f"; \
	done
	@rm -rf .a64check
	@echo "ARM64 交叉编译全部通过"

clean:
	rm -rf bin .a64check

.PHONY: all bin test check-arm64 clean
