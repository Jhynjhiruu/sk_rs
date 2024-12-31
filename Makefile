all: rom

TARGET := sk_rs

ROM := $(TARGET).z64

DEBUG := 0

ifeq ($(DEBUG),0)
	MODE_STR := release
	MODE_FLAG := --release
else
	MODE_STR := debug
	MODE_FLAG := 
endif

OBJCOPY := llvm-objcopy
DD := dd
CARGO := cargo
CARGOFLAGS :=
SPIMDISASM := spimdisasm
SPIMFLAGS := singleFileDisasm $(ROM) disasm --vram 0x9FC00000 --disasm-unknown
RM := rm
IQUECRYPT := iquecrypt
AES := sk.aes
KEY := 00000000000000000000000000000000
IV := 00000000000000000000000000000000

CWD := $(shell pwd)
TARGET_DIR := $(CWD)/target
BUILD_DIR := $(TARGET_DIR)/mips-ultra64-cpu/$(MODE_STR)
RUST_OBJ := $(BUILD_DIR)/$(TARGET)

%.z64: $(TARGET_DIR)/%.bin
	$(DD) if=$< of=$@ bs=16K conv=sync status=none

$(TARGET_DIR)/%.bin: $(RUST_OBJ)
	$(OBJCOPY) -O binary $< $@

$(RUST_OBJ): targets/linker.ld Cargo.toml build.rs src/main.rs
	$(CARGO) build $(MODE_FLAG) $(CARGOFLAGS)

$(AES): $(ROM)
	$(IQUECRYPT) encrypt -app $< -key $(KEY) -iv $(IV) -o $@

rom: $(ROM)

aes: $(AES)

asm: disasm/$(TARGET)_9FC00000.text.s

disasm/%.s: rom
	$(SPIMDISASM) $(SPIMFLAGS)

clean:
	$(CARGO) clean
	$(RM) -rf disasm
	$(RM) -f $(ROM)
	$(RM) -f $(AES)

.PHONY: rom asm all clean aes

.DEFAULT: all

-include $(RUST_OBJ).d