//! Test fixture for unwind-map, linked by `build.sh` into a freestanding
//! static executable for each architecture. The binaries are only parsed by
//! the tests, never run.
//!
//! It contains a few functions of different shapes (leaf, recursive, large
//! stack frame, many arguments, indirect calls, a non-exported helper) plus
//! one hand-written assembly function without CFI directives, which therefore
//! has no FDE and should show up in `--gaps`.

#![no_std]

use core::hint::black_box;

#[no_mangle]
#[inline(never)]
pub extern "C" fn leaf_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn fib(n: u32) -> u64 {
    if n < 2 {
        n as u64
    } else {
        fib(n - 1).wrapping_add(fib(n - 2))
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn big_frame(seed: u64) -> u64 {
    // Filled element by element (not zero-initialised) so the compiler does
    // not emit a call to memset, which a freestanding binary does not have.
    let mut buf = core::mem::MaybeUninit::<[u64; 512]>::uninit();
    let p = buf.as_mut_ptr() as *mut u64;
    for i in 0..512 {
        unsafe { p.add(i).write(seed.wrapping_mul(i as u64 + 1)) };
    }
    let buf = black_box(unsafe { buf.assume_init_ref() });
    buf.iter().fold(0, |acc, x| acc ^ x)
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn many_args(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u64 {
    a ^ b.rotate_left(1)
        ^ c.rotate_left(2)
        ^ d.rotate_left(3)
        ^ e.rotate_left(4)
        ^ f.rotate_left(5)
        ^ g.rotate_left(6)
        ^ h.rotate_left(7)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn dispatch(op: u32, a: u64, b: u64) -> u64 {
    let table: [extern "C" fn(u64, u64) -> u64; 3] = [leaf_add, mix, leaf_add];
    black_box(table)[(op % 3) as usize](a, b)
}

/// Not exported: ends up as a local, mangled symbol.
#[inline(never)]
extern "C" fn mix(a: u64, b: u64) -> u64 {
    local_helper(a) ^ b
}

#[inline(never)]
fn local_helper(x: u64) -> u64 {
    x.rotate_left(7) ^ 0x5a5a
}

extern "C" {
    fn asm_no_cfi(a: u64, b: u64) -> u64;
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".text",
    ".globl asm_no_cfi",
    ".type asm_no_cfi, @function",
    ".p2align 4",
    "asm_no_cfi:",
    "lea rax, [rdi + rsi]",
    "ret",
    ".size asm_no_cfi, . - asm_no_cfi",
);

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".text",
    ".globl asm_no_cfi",
    ".type asm_no_cfi, @function",
    ".p2align 4",
    "asm_no_cfi:",
    "mov eax, [esp + 4]",
    "mov edx, [esp + 8]",
    "add eax, [esp + 12]",
    "adc edx, [esp + 16]",
    "ret",
    ".size asm_no_cfi, . - asm_no_cfi",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".text",
    ".globl asm_no_cfi",
    ".type asm_no_cfi, %function",
    ".p2align 4",
    "asm_no_cfi:",
    "add x0, x0, x1",
    "ret",
    ".size asm_no_cfi, . - asm_no_cfi",
);

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut acc = leaf_add(black_box(1), black_box(2));
    acc ^= fib(black_box(20));
    acc ^= big_frame(black_box(acc));
    acc ^= many_args(acc, 1, 2, 3, 4, 5, 6, black_box(7));
    acc ^= dispatch(black_box(1), acc, 9);
    acc ^= unsafe { asm_no_cfi(black_box(4), black_box(5)) };
    exit((acc & 0x7f) as i32)
}

fn exit(code: i32) -> ! {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("syscall", in("rax") 60, in("rdi") code, options(noreturn));
        #[cfg(target_arch = "x86")]
        core::arch::asm!("mov ebx, {0}", "int 0x80", in(reg) code, in("eax") 1, options(noreturn));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("svc 0", in("x8") 93, in("x0") code, options(noreturn));
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}
