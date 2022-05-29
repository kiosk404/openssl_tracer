APPS = openssl_trace

UPROBE ?= ./bpf/

CMD_CLANG ?= clang
CMD_LLC ?= llc
CMD_STRIP ?= llvm-strip
CMD_RM ?= rm
CMD_GO ?= go
CMD_BPFTOOL ?= bpftool
CMD_MD5 ?= md5sum

STYLE  ?= "{BasedOnStyle: Google, IndentWidth: 4}"
PARALLEL = $(shell grep -c ^processor /proc/cpuinfo)
BPFHEADER = -I./bpf \

EXTRA_CFLAGS ?= -O2 -mcpu=v1 \
#	-DDEBUG_PRINT	\
#	-Wno-pointer-sign

#
# tools version
#

CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | tr -d '[:alpha:]' | tr -d '[:space:]' | cut -d'.' -f1)
GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | awk '{print $$3}' | sed 's:go::g' | cut -d. -f1,2)
GO_VERSION_MAJ = $(shell echo $(GO_VERSION) | cut -d'.' -f1)
GO_VERSION_MIN = $(shell echo $(GO_VERSION) | cut -d'.' -f2)

#
# environment
#

UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

#
# Target Arch
#

ifeq ($(UNAME_M),x86_64)
   ARCH = x86_64
   LINUX_ARCH = x86
   GO_ARCH = amd64
endif

ifeq ($(UNAME_M),aarch64)
   ARCH = arm64
   LINUX_ARCH = arm64
   GO_ARCH = arm64
endif

#
# BPF Source file
#

TARGETS := bpf/$(APPS)

# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=.bpf.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
KERN_OBJECTS_NOCORE = ${KERN_SOURCES:.c=.nocore}

#
# include vpath
#

KERN_RELEASE ?= $(UNAME_R)
KERN_BUILD_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH ?= $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BUILD_PATH)))

BPF_NOCORE_TAG = $(subst .,_,$(KERN_RELEASE)).$(subst .,_,$(VERSION))

.PHONY: env
env:
	@echo ---------------------------------------
	@echo "Makefile Environment:"
	@echo ---------------------------------------
	@echo "PARALLEL                 $(PARALLEL)"
	@echo ---------------------------------------
	@echo "CLANG_VERSION            $(CLANG_VERSION)"
	@echo "GO_VERSION               $(GO_VERSION)"
	@echo ---------------------------------------
	@echo "CMD_CLANG                $(CMD_CLANG)"
	@echo "CMD_GO                   $(CMD_GO)"
	@echo "CMD_LLC                  $(CMD_LLC)"
	@echo "CMD_MD5                  $(CMD_MD5)"
	@echo "CMD_BPFTOOL              $(CMD_BPFTOOL)"
	@echo "CMD_STRIP                $(CMD_STRIP)"
	@echo ---------------------------------------
	@echo "UNAME_M                  $(UNAME_M)"
	@echo "UNAME_R                  $(UNAME_R)"
	@echo "ARCH                     $(ARCH)"
	@echo "LINUX_ARCH               $(LINUX_ARCH)"
	@echo ---------------------------------------
	@echo "KERN_RELEASE             $(KERN_RELEASE)"
	@echo "KERN_BUILD_PATH          $(KERN_BUILD_PATH)"
	@echo "KERN_SRC_PATH            $(KERN_SRC_PATH)"
	@echo ---------------------------------------
	@echo "GO_ARCH                  $(GO_ARCH)"
	@echo "KERN_SOURCES             $(KERN_SOURCES)"
	@echo "KERN_OBJECTS             $(KERN_OBJECTS)"
	@echo ---------------------------------------

vmlinux:
	$(CMD_BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	$(CMD_RM) -f bpf/$(APPS).bpf.o
	$(CMD_RM) -f bpf/$(APPS).bpf.d
	$(CMD_RM) -f main

.PHONY: $(KERN_OBJECTS)
$(KERN_OBJECTS): %.o: %.c
	$(CMD_CLANG) -D__TARGET_ARCH_$(LINUX_ARCH) \
		$(EXTRA_CFLAGS) \
		$(BPFHEADER) \
		-target bpfel -c $< -o $(subst kern/,user/bytecode/,$@) \
		-fno-ident -fdebug-compilation-dir . -g -D__BPF_TARGET_MISSING="GCC error \"The eBPF is using target specific macros, please provide -target\"" \
		-MD -MP

.PHONY: ebpf
ebpf: $(KERN_OBJECTS)

# Format the code
format:
	@echo "  ->  Formatting code"
	@clang-format -i -style=$(STYLE) bpf/*.c
	@clang-format -i -style=$(STYLE) bpf/common.h

# Build the ebpf code
.PHONY: build
build:
	$(CMD_GO) build -o $(APPS)