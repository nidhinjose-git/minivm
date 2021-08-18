// SPDX-License-Identifier: Apache-2.0
#![feature(asm, naked_functions)]

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit};
use mmarinus::{perms, Kind, Map};

#[naked]
pub unsafe extern "sysv64" fn code() -> ! {
    asm!(
        "
.code16
code_start:
    hlt
code_end:
.fill((4096 - (code_end - code_start)))
    ",
        options(noreturn)
    )
}

fn main() {
    const MEM_SIZE: usize = 0x1000;

    let kvm = Kvm::new().unwrap();
    let vm = kvm.create_vm().unwrap();

    let mut address_space = Map::map(MEM_SIZE)
        .anywhere()
        .anonymously()
        .known::<perms::ReadWrite>(Kind::Private)
        .unwrap();

    let code = unsafe { std::slice::from_raw_parts(code as *const u8, 4096) };
    let target = unsafe { std::slice::from_raw_parts_mut(address_space.as_mut_ptr(), 4096) };

    target.copy_from_slice(code);

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: address_space.size() as _,
        userspace_addr: address_space.addr() as _,
        flags: 0,
    };

    unsafe {
        vm.set_user_memory_region(mem_region).unwrap();
    }

    let vcpu = vm.create_vcpu(0).unwrap();
    let mut sregs = vcpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    regs.rflags = 2;
    regs.rax = 1;
    regs.rbx = 2;
    regs.rip = 0x0;
    vcpu.set_regs(&regs).unwrap();

    loop {
        match vcpu.run().unwrap() {
            VcpuExit::Hlt => break,
            exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
        }
    }

    let regs = vcpu.get_regs().unwrap();
    assert_eq!(regs.rax, 3);

    println!("Everything works!");
}
