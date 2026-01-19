/* Linker script for bare-metal KVM guest */

ENTRY(_start)

/* Guest code is loaded at 0x10000 by the VMM */
GUEST_BASE = 0x10000;

SECTIONS
{
    . = GUEST_BASE;

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
