/* Linker script for operation binary (loaded at OPERATION_LOAD_ADDR) */

ENTRY(_start)

/* Operations are loaded at 0x20000 by the VMM */
OPERATION_BASE = 0x20000;

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
