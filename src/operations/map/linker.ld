/* Linker script for operation binary (loaded at OPERATION_LOAD_ADDR) */

ENTRY(_start)

/* Operations are loaded at 0x30000 by the VMM (raised from 0x20000, then 0x22000; see shared OPERATION_LOAD_ADDR) */
OPERATION_BASE = 0x30000;

SECTIONS
{
    . = OPERATION_BASE;

    .text : {
        *(.text._start)
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.eh_frame)
        *(.note*)
        *(.comment*)
    }
}
