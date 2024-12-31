OUTPUT_FORMAT ("elf32-ntradbigmips")
OUTPUT_ARCH (mips)

ENTRY(_startup)

MEMORY {
    SECRAM  (RWX) : ORIGIN = 0x9FC00000, LENGTH = 0x00010000
    SCRATCH (RWX) : ORIGIN = 0x9FC40000, LENGTH = 0x00008000
    FLASH   (R)   : ORIGIN = 0x00000000, LENGTH = LENGTH(SECRAM)
    DRAM    (RWX) : ORIGIN = 0x80000000, LENGTH = 0x00800000
}

__entry_offset = 0x0000;
__int_handler_offset = 0x0380;

__entry = ORIGIN(SECRAM) + __entry_offset;
__int_handler = ORIGIN(SECRAM) + __int_handler_offset;

SECTIONS {
    __romPos = 0;

    .dram ORIGIN(DRAM) (NOLOAD) : {
        __dram_start = .;
        *(.dram*)
        . = ALIGN(16);
         __dram_end = .;
         __dram_size = (__dram_end - __dram_start);
    } > DRAM

    __load_start = __romPos;

    entry_ROM_START = __romPos;
    .entry __entry : AT(entry_ROM_START) {
        __entry_start = .;
        KEEP(*(.entry_uncached));
        *(.entry*);
        . = ALIGN(16);
        __entry_end = .;
        __entry_size = (__entry_end - __entry_start);
    } > SECRAM
    __romPos += SIZEOF(.entry);
    __romPos = ALIGN(__romPos, 16);
    entry_ROM_END = __romPos;

    ASSERT(SIZEOF(.entry) < __int_handler_offset, ".entry section is too large")

    __romPos = __int_handler_offset;
    int_handler_ROM_START = __romPos;
    .int_handler __int_handler : AT(int_handler_ROM_START) {
        __int_handler_start = .;
        KEEP(*(.int_handler*));
        . = ALIGN(16);
        __int_handler_end = .;
        __int_handler_size = (__int_handler_end - __int_handler_start);
    } > SECRAM
    __romPos += SIZEOF(.int_handler);
    __romPos = ALIGN(__romPos, 16);
    int_handler_ROM_END = __romPos;

    boot_ROM_START = __romPos;
    .boot ALIGN(16) : AT(boot_ROM_START) {
        __boot_start = .;
        KEEP(*(.boot*));
        . = ALIGN(16);
        __boot_end = .;
        __boot_size = (__boot_end - __boot_start);
    } > SECRAM
    __romPos += SIZEOF(.boot);
    __romPos = ALIGN(__romPos, 16);
    boot_ROM_END = __romPos;

    text_ROM_START = __romPos;
    .text ALIGN(16) : AT(text_ROM_START) {
        __text_start = .;
        *(.text*);
        . = ALIGN(16);
        __text_end = .;
        __text_size = (__text_end - __text_start);
    } > SECRAM
    __romPos += SIZEOF(.text);
    __romPos = ALIGN(__romPos, 16);
    text_ROM_END = __romPos;

    data_ROM_START = __romPos;
    .data ALIGN(16) : AT(data_ROM_START) {
        __data_start = .;
        *(.data*);
        . = ALIGN(16);
        __data_end = .;
        __data_size = (__data_end - __data_start);
    } > SECRAM
    __romPos += SIZEOF(.data);
    __romPos = ALIGN(__romPos, 16);
    data_ROM_END = __romPos;

    rodata_ROM_START = __romPos;
    .rodata ALIGN(16) : AT(rodata_ROM_START) SUBALIGN(16) {
        __rodata_start = .;
        *(.rodata*);
        . = ALIGN(16);
        __rodata_end = .;
        __rodata_size = (__rodata_end - __rodata_start);
    } > SECRAM
    __romPos += SIZEOF(.rodata);
    __romPos = ALIGN(__romPos, 16);
    rodata_ROM_END = __romPos;

    __load_end = __romPos;
    __load_size = __load_end - __load_start;

    ASSERT(__load_size < LENGTH(FLASH), "ROM data is too large")

    . = ALIGN(16);
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss)
        *(.bss*)
        *(.gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(16);
         __bss_end = .;
         __bss_size = (__bss_end - __bss_start);
    } > SECRAM

    __heap_start = __bss_end;
    __heap_end = ORIGIN(SECRAM) + LENGTH(SECRAM);
    __heap_len = __heap_end - __heap_start;

    .pad : AT(LENGTH(SECRAM) - 4) {
        LONG(0x00000000);
    }

    .stack ORIGIN(SCRATCH) + LENGTH(SCRATCH) - __stack_size (NOLOAD) : {
        __stack_start = .;
        KEEP(*(.stack));
        KEEP(*(.stack*));
        . = ALIGN(16);
        __stack_end = .;
        __stack_size = (__stack_end - __stack_start);
    } > SCRATCH

    virage2             = 0xBFCA0000;

    /DISCARD/ : {
        *(.MIPS.*)
        *(.comment)
        *(.mdebug.*)
        *(.pdr)
        *(.reginfo)
        *(.eh_frame)

        /*
         * We may need the global offset table some day.
         * Our target is currently set with a static relocation-model, so this
         * might not be needed after all.
         */
        *(.got)
    }
}