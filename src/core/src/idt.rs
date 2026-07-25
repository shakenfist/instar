//! Minimal interrupt descriptor table (IDT) for the bare-metal guest.
//!
//! Without an IDT the guest has no exception handlers, so *any* CPU
//! exception — an invalid opcode (`#UD`) from a codegen miscompile, a
//! page fault from a stray pointer, a `#GP` from a stack problem —
//! escalates through `#DF` to a triple fault. KVM surfaces that to the
//! VMM only as an opaque `VcpuExit::Shutdown` ("possible triple fault"):
//! no vector, no faulting address, no operation result. Diagnosing one
//! historically meant bisecting with a hardware watchpoint (see the
//! `amend` codegen-miscompile investigation and issue #375).
//!
//! This module installs a 32-entry IDT covering the Intel-defined
//! exception vectors (`0..=31`). Every gate points at a small stub that
//! normalizes the CPU's stack frame — pushing a dummy error code for the
//! vectors that don't push one — and tail-calls [`isr_handler`], which
//! reports the vector and faulting `RIP` to the host over the same
//! serial `error` channel the panic handler uses, then halts. A triple
//! fault becomes a clean, described failure the host can print, and the
//! guest ops no longer depend on a particular codegen outcome (their
//! `#[inline(never)]` discipline) *silently* holding: a recurrence now
//! reports `cpu-exception` with the faulting address instead of vanishing
//! into a shutdown.
//!
//! Hardware interrupts stay masked (the VMM boots the guest with
//! `RFLAGS.IF = 0` and configures no interrupt controller), so only
//! synchronous exceptions reach these handlers — no IRQ plumbing needed.

use core::arch::{asm, global_asm};

use crate::serial::{debug_print, send_error};

/// Number of IDT entries installed. Covers Intel exception vectors
/// `0..=31`; vectors `>= 32` (hardware IRQs, software interrupts) never
/// fire in this environment.
const IDT_ENTRIES: usize = 32;

/// Code segment selector the VMM installs in the guest GDT
/// (`CODE_SELECTOR` in `vmm/src/main.rs`). Every IDT gate references it.
const CODE_SELECTOR: u16 = 0x08;

/// Gate type/attribute byte: present (`P=1`), DPL 0, 64-bit interrupt
/// gate (`type=0xE`) — i.e. `0x8E`.
const GATE_TYPE_ATTR: u8 = 0x8E;

/// A 64-bit IDT gate descriptor (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn zero() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Point this gate at `handler` (a stub's absolute address).
    fn set_handler(&mut self, handler: u64) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = CODE_SELECTOR;
        self.ist = 0;
        self.type_attr = GATE_TYPE_ATTR;
        self.reserved = 0;
    }
}

/// The IDT itself, living in the guest's `.bss`.
static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::zero(); IDT_ENTRIES];

/// Re-entrancy guard: if a fault occurs *while* reporting a fault, halt
/// immediately rather than risk an endless fault storm (interrupts are
/// masked, so a second exception would just re-vector here forever).
static mut IN_HANDLER: bool = false;

/// The `lidt` operand: a 2-byte limit followed by the 8-byte base.
#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

extern "C" {
    /// Table of the 32 exception-stub entry points, emitted by the
    /// `global_asm!` block below.
    static ISR_STUBS: [unsafe extern "C" fn(); IDT_ENTRIES];
}

/// The CPU-pushed interrupt stack frame plus the two values the stubs
/// push (vector, then error code beneath it). Laid out to match the
/// stack `RSP` points at when `isr_handler` is entered.
#[repr(C)]
struct IsrFrame {
    /// Exception vector (pushed by the stub).
    vector: u64,
    /// Hardware error code, or 0 for vectors that don't push one.
    error_code: u64,
    /// Faulting instruction pointer (pushed by the CPU).
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// Install the IDT. Call once, as early as possible in `_start`, before
/// any code that could fault.
pub fn install() {
    unsafe {
        // Fill each gate through a raw pointer to avoid taking a
        // reference to the `static mut` (which `static_mut_refs` forbids).
        let idt_ptr = core::ptr::addr_of_mut!(IDT) as *mut IdtEntry;
        for i in 0..IDT_ENTRIES {
            let handler = ISR_STUBS[i] as usize as u64;
            (*idt_ptr.add(i)).set_handler(handler);
        }

        let idtr = Idtr {
            limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: idt_ptr as u64,
        };
        asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// Common Rust exception handler. Reports the vector and faulting `RIP`
/// to the host, then halts. Never returns — a caught exception ends the
/// operation (the host sees an `error` message and no result).
///
/// # Safety
///
/// Called only from the assembly stubs with `RDI` pointing at a valid
/// [`IsrFrame`] on the exception stack.
#[no_mangle]
unsafe extern "C" fn isr_handler(frame: *const IsrFrame) -> ! {
    // Guard against faulting inside the reporting path.
    let guard = core::ptr::addr_of_mut!(IN_HANDLER);
    if *guard {
        halt();
    }
    *guard = true;

    let f = &*frame;
    debug_print("core: CPU exception\n");
    // The status field carries the vector; the sector field carries the
    // faulting RIP so the host can point at the exact instruction.
    send_error("cpu-exception", "guest", f.rip, f.vector as u32);
    halt();
}

/// Halt the CPU forever.
fn halt() -> ! {
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

// Exception stubs and the stub-address table.
//
// Each stub establishes a uniform stack frame — `[vector][error_code]` —
// before tail-calling `isr_handler`. Vectors that the CPU pushes an error
// code for (8, 10, 11, 12, 13, 14, 17, 21) push only the vector; the rest
// push a dummy `0` error code first so the frame layout is identical.
//
// `isr_common` passes `RSP` (the frame pointer) in `RDI`, aligns the
// stack, and calls the Rust handler, which never returns.
//
// Rust `global_asm!` defaults to Intel syntax.
global_asm!(
    r#"
.section .text

isr_common:
    mov rdi, rsp        // &IsrFrame
    and rsp, -16        // 16-byte align for the SysV call (never returns)
    call isr_handler
1:
    hlt
    jmp 1b

isr_stub_0:
    push 0
    push 0
    jmp isr_common
isr_stub_1:
    push 0
    push 1
    jmp isr_common
isr_stub_2:
    push 0
    push 2
    jmp isr_common
isr_stub_3:
    push 0
    push 3
    jmp isr_common
isr_stub_4:
    push 0
    push 4
    jmp isr_common
isr_stub_5:
    push 0
    push 5
    jmp isr_common
isr_stub_6:
    push 0
    push 6
    jmp isr_common
isr_stub_7:
    push 0
    push 7
    jmp isr_common
isr_stub_8:
    push 8
    jmp isr_common
isr_stub_9:
    push 0
    push 9
    jmp isr_common
isr_stub_10:
    push 10
    jmp isr_common
isr_stub_11:
    push 11
    jmp isr_common
isr_stub_12:
    push 12
    jmp isr_common
isr_stub_13:
    push 13
    jmp isr_common
isr_stub_14:
    push 14
    jmp isr_common
isr_stub_15:
    push 0
    push 15
    jmp isr_common
isr_stub_16:
    push 0
    push 16
    jmp isr_common
isr_stub_17:
    push 17
    jmp isr_common
isr_stub_18:
    push 0
    push 18
    jmp isr_common
isr_stub_19:
    push 0
    push 19
    jmp isr_common
isr_stub_20:
    push 0
    push 20
    jmp isr_common
isr_stub_21:
    push 21
    jmp isr_common
isr_stub_22:
    push 0
    push 22
    jmp isr_common
isr_stub_23:
    push 0
    push 23
    jmp isr_common
isr_stub_24:
    push 0
    push 24
    jmp isr_common
isr_stub_25:
    push 0
    push 25
    jmp isr_common
isr_stub_26:
    push 0
    push 26
    jmp isr_common
isr_stub_27:
    push 0
    push 27
    jmp isr_common
isr_stub_28:
    push 0
    push 28
    jmp isr_common
isr_stub_29:
    push 0
    push 29
    jmp isr_common
isr_stub_30:
    push 0
    push 30
    jmp isr_common
isr_stub_31:
    push 0
    push 31
    jmp isr_common

.section .rodata
.balign 8
.global ISR_STUBS
ISR_STUBS:
    .quad isr_stub_0
    .quad isr_stub_1
    .quad isr_stub_2
    .quad isr_stub_3
    .quad isr_stub_4
    .quad isr_stub_5
    .quad isr_stub_6
    .quad isr_stub_7
    .quad isr_stub_8
    .quad isr_stub_9
    .quad isr_stub_10
    .quad isr_stub_11
    .quad isr_stub_12
    .quad isr_stub_13
    .quad isr_stub_14
    .quad isr_stub_15
    .quad isr_stub_16
    .quad isr_stub_17
    .quad isr_stub_18
    .quad isr_stub_19
    .quad isr_stub_20
    .quad isr_stub_21
    .quad isr_stub_22
    .quad isr_stub_23
    .quad isr_stub_24
    .quad isr_stub_25
    .quad isr_stub_26
    .quad isr_stub_27
    .quad isr_stub_28
    .quad isr_stub_29
    .quad isr_stub_30
    .quad isr_stub_31
"#
);
