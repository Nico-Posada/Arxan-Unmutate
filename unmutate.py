import os
HEADLESS = "IDA_IS_INTERACTIVE" not in os.environ or os.environ["IDA_IS_INTERACTIVE"] != "1"

if HEADLESS:
    # TODO actually implement headless properly
    import ida

import ida_ua, idautils, idc, idaapi, ida_bytes, ida_funcs, ida_hexrays, ida_lines, ida_idp, ida_auto
from keystone import Ks, KS_ARCH_X86, KS_MODE_64 # pip install keystone-engine
import ctypes

# SETTINGS
DEOBF_START = 0x7FF6E6A75D20
DO_PATCH = 1

# marker just to indicate to myself that there can be more checks
# done, but it's just not worth it
SKIP_LESSER_CHECKS = False

# set up a global instance for keystone
ks = Ks(KS_ARCH_X86, KS_MODE_64)

def get_frame(addr) -> list[ida_ua.insn_t]:
    result = []
    while True:
        cur_insn = ida_ua.insn_t()
        idc.create_insn(addr)
        insn_len = ida_ua.decode_insn(cur_insn, addr)
        assert insn_len != 0, f"Failed to decode instruction @ {addr:#x}"
        result.append(cur_insn)

        mnem = cur_insn.get_canon_mnem()
        if mnem == "retn" or mnem == "jmp":
            return result
        
        addr += insn_len

class MutationHandler:
    __slots__ = ("mutation_handlers",)

    def __init__(self):
        self.mutation_handlers = []

    def register_handler(self, fn):
        if fn not in self.mutation_handlers:
            self.mutation_handlers.append(fn)
    
    def find_mutation(self, cur_frame):
        # run through all handlers, check if any match
        for fn in self.mutation_handlers:
            result = fn(cur_frame)
            if result is not None:
                # return is (unmutated bytes, values to pop, addrs to explore)
                return result
        
        # if none match, return None
        return None

unmutator = MutationHandler()

############################################
############################################
# push handlers
############################################
############################################

@unmutator.register_handler
def push_handler1(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FC85B9CF 48 89 5C 24 F8                                mov     [rsp-8], rbx
    .text:00007FF6FC85B9D4 48 8D 64 24 F8                                lea     rsp, [rsp-8]
    """
    global ks
    if len(cur_frame) < 2:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "mov" or \
        i0.Op1.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i0.Op1.reg, 8) != "rsp" or \
        ctypes.c_int64(i0.Op1.addr).value != -8 or \
        i0.Op2.type != ida_ua.o_reg:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "lea" or \
        i1.Op1.type != ida_ua.o_reg or \
        i1.Op2.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i1.Op2.reg, 8) != "rsp" or \
        ctypes.c_int64(i1.Op2.addr).value != -8:
        return None
    
    # construct unmutated insn
    reg = ida_idp.get_reg_name(i0.Op2.reg, 8)

    template = "push {reg}"
    asm = template.format(reg=reg)
    assembled, _ = ks.asm(asm, as_bytes=True)
    return assembled, 2, ()

@unmutator.register_handler
def push_handler2(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FB5C753C 48 8D 64 24 F8                                lea     rsp, [rsp-8]
    .text:00007FF6FB5C7541 48 89 3C 24                                   mov     [rsp], rdi
    """
    global ks
    if len(cur_frame) < 2:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "lea" or \
        i0.Op1.type != ida_ua.o_reg or \
        i0.Op2.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i0.Op2.reg, 8) != "rsp" or \
        ctypes.c_int64(i0.Op2.addr).value != -8:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "mov" or \
        i1.Op1.type != ida_ua.o_phrase or \
        ida_idp.get_reg_name(i1.Op1.reg, 8) != "rsp" or \
        i1.Op2.type != ida_ua.o_reg:
        return None
    
    # construct unmutated insn
    reg = ida_idp.get_reg_name(i1.Op2.reg, 8)

    template = "push {reg}"
    asm = template.format(reg=reg)
    assembled, _ = ks.asm(asm, as_bytes=True)
    return assembled, 2, ()

############################################
############################################
# pop handlers
############################################
############################################

@unmutator.register_handler
def pop_handler1(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FE86EFB9 48 8D 64 24 08                                lea     rsp, [rsp+8]
    .text:00007FF6FE86EFBE 4C 8B 7C 24 F8                                mov     r15, [rsp-8]
    """
    global ks
    if len(cur_frame) < 2:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "lea" or \
        i0.Op1.type != ida_ua.o_reg or \
        i0.Op2.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i0.Op2.reg, 8) != "rsp" or \
        i0.Op2.addr != 8:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "mov" or \
        i1.Op1.type != ida_ua.o_reg or \
        i1.Op2.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i1.Op2.reg, 8) != "rsp" or \
        ctypes.c_int64(i1.Op2.addr).value != -8:
        return None
    
    # construct unmutated insn
    reg = ida_idp.get_reg_name(i1.Op1.reg, 8)

    template = "pop {reg}"
    asm = template.format(reg=reg)
    assembled, _ = ks.asm(asm, as_bytes=True)
    return assembled, 2, ()

@unmutator.register_handler
def pop_handler2(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FEB78165 4C 8B 2C 24                                   mov     r13, [rsp]
    .text:00007FF6FEB78169 48 8D 64 24 08                                lea     rsp, [rsp+8]
    """
    global ks
    if len(cur_frame) < 2:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "mov" or \
        i0.Op1.type != ida_ua.o_reg or \
        i0.Op2.type != ida_ua.o_phrase or \
        ida_idp.get_reg_name(i0.Op2.reg, 8) != "rsp":
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "lea" or \
        i1.Op1.type != ida_ua.o_reg or \
        ida_idp.get_reg_name(i1.Op1.reg, 8) != "rsp" or \
        i1.Op2.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i1.Op2.reg, 8) != "rsp" or \
        i1.Op2.addr != 8:
        return None
    
    # construct unmutated insn
    reg = ida_idp.get_reg_name(i0.Op1.reg, 8)

    template = "pop {reg}"
    asm = template.format(reg=reg)
    assembled, _ = ks.asm(asm, as_bytes=True)
    return assembled, 2, ()

############################################
############################################
# retn handlers
############################################
############################################

@unmutator.register_handler
def retn_handler1(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FEB87922 48 8D 64 24 08                                lea     rsp, [rsp+8]
    .text:00007FF6FEB87927 FF 64 24 F8                                   jmp     qword ptr [rsp-8]
    """
    global ks
    if len(cur_frame) < 2:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "lea" or \
        i0.Op1.type != ida_ua.o_reg or \
        ida_idp.get_reg_name(i0.Op1.reg, 8) != "rsp" or \
        i0.Op2.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i0.Op2.reg, 8) != "rsp" or \
        i0.Op2.addr != 8:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "jmp" or \
        i1.Op1.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i1.Op1.reg, 8) != "rsp" or \
        ctypes.c_int64(i1.Op1.addr).value != -8:
        return None
    
    # retn is always the same, no need for any ks stuff
    return b"\xC3", 2, ()

############################################
############################################
# mov handlers
############################################
############################################

@unmutator.register_handler
def mov_handler1(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FBA1A70C 41 51                                         push    r9
    .text:00007FF6FBA1A70E 41 5D                                         pop     r13
    """
    global ks
    if len(cur_frame) < 2:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "push" or \
        i0.Op1.type != ida_ua.o_reg:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "pop" or \
        i0.Op1.type != ida_ua.o_reg:
        return None
    
    # if the sequence is something like `push rax; pop rbx`, that's only 2 bytes
    # but `mov rbx, rax` is 3 bytes, so if we encounter this we just have to truncate to 32 bit insns
    mutated_len = i0.size + i1.size
    reg_width = 8 if mutated_len > 2 else 4

    if reg_width == 4:
        print(f"Had to compress mov instruction @ {i0.ea:#x}, check if you can manually fix")

    src = ida_idp.get_reg_name(i0.Op1.reg, reg_width)
    dst = ida_idp.get_reg_name(i1.Op1.reg, reg_width)

    template = "mov {dst}, {src}"
    asm = template.format(dst=dst, src=src)
    assembled, _ = ks.asm(asm, as_bytes=True)
    return assembled, 2, ()

@unmutator.register_handler
def mov_handler2(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FC8F8B26 41 57                                         push    r15
    .text:00007FF6FC8F8B28 8B 3C 24                                      mov     edi, [rsp]
    .text:00007FF6FC8F8B2B 41 5F                                         pop     r15
    """
    global ks
    if len(cur_frame) < 3:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "push" or \
        i0.Op1.type != ida_ua.o_reg:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "mov" or \
        i1.Op1.type != ida_ua.o_reg or \
        i1.Op2.type != ida_ua.o_phrase or \
        ida_idp.get_reg_name(i1.Op2.reg, 8) != "rsp":
        return None
    
    # 3rd line
    i2 = cur_frame[2]
    if i2.get_canon_mnem() != "pop" or \
        i2.Op1.type != ida_ua.o_reg:
        return None
    
    reg_width = ida_ua.get_dtype_size(i1.Op1.dtype)
    dst = ida_idp.get_reg_name(i1.Op1.reg, reg_width)
    src = ida_idp.get_reg_name(i0.Op1.reg, reg_width)

    template = "mov {dst}, {src}"
    asm = template.format(dst=dst, src=src)
    assembled, _ = ks.asm(asm, as_bytes=True)
    return assembled, 3, ()

############################################
############################################
# condj handlers
############################################
############################################

@unmutator.register_handler
def condj_handler1(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FE673F3F 41 54                                         push    r12
    .text:00007FF6FE673F41 49 BC C9 05 9A E4 F6 7F 00 00                 mov     r12, offset sub_7FF6E49A05C9
    .text:00007FF6FE673F4B FF 34 24                                      push    qword ptr [rsp]
    .text:00007FF6FE673F4E 4C 89 64 24 08                                mov     [rsp+8], r12
    .text:00007FF6FE673F53 41 5C                                         pop     r12
    .text:00007FF6FE673F55 51                                            push    rcx
    .text:00007FF6FE673F56 52                                            push    rdx
    .text:00007FF6FE673F57 48 8B 4C 24 10                                mov     rcx, [rsp+10h]
    .text:00007FF6FE673F5C 48 BA 7D 1C 92 F7 F6 7F 00 00                 mov     rdx, offset sub_7FF6F7921C7D
    .text:00007FF6FE673F66 48 0F 45 CA                                   cmov__  rcx, rdx
    .text:00007FF6FE673F6A 48 89 4C 24 10                                mov     [rsp+10h], rcx
    .text:00007FF6FE673F6F 5A                                            pop     rdx
    .text:00007FF6FE673F70 59                                            pop     rcx
    .text:00007FF6FE673F71 C3                                            retn
    """
    global ks
    if len(cur_frame) < 14:
        return None
    
    # going to do more lax checks for this since it's so big, odds of there being a sequence
    # just like this with these mnems in order and it not being a mutation is just impossible

    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "push" or \
        i0.Op1.type != ida_ua.o_reg:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "mov" or \
        i1.Op2.type != ida_ua.o_imm or \
        SKIP_LESSER_CHECKS:
        return None
    
    # 3rd line
    i2 = cur_frame[2]
    if i2.get_canon_mnem() != "push" or \
        i2.Op1.type != ida_ua.o_phrase:
        return None
    
    # 4th line
    i3 = cur_frame[3]
    if i3.get_canon_mnem() != "mov" or \
        i3.Op2.type != ida_ua.o_reg or \
        SKIP_LESSER_CHECKS:
        return None
    
    # 5th line
    i4 = cur_frame[4]
    if i4.get_canon_mnem() != "pop" or \
        i4.Op1.type != ida_ua.o_reg:
        return None
    
    # 6th line
    i5 = cur_frame[5]
    if i5.get_canon_mnem() != "push" or \
        i5.Op1.type != ida_ua.o_reg:
        return None
    
    # 7th line
    i6 = cur_frame[6]
    if i6.get_canon_mnem() != "push" or \
        i6.Op1.type != ida_ua.o_reg:
        return None
    
    # 8th line
    i7 = cur_frame[7]
    if i7.get_canon_mnem() != "mov" or \
        i7.Op1.type != ida_ua.o_reg or \
        SKIP_LESSER_CHECKS:
        return None
    
    # 9th line
    i8 = cur_frame[8]
    if i8.get_canon_mnem() != "mov" or \
        i8.Op1.type != ida_ua.o_reg or \
        i8.Op2.type != ida_ua.o_imm:
        return None
    
    # 10th line
    i9 = cur_frame[9]
    if i9.get_canon_mnem()[:4] != "cmov" or \
        i9.Op1.type != ida_ua.o_reg or \
        i9.Op2.type != ida_ua.o_reg:
        return None
    
    # dont need to do the rest of them, we know we're in the right spot
    SKIP_LESSER_CHECKS

    jmp = i1.Op2.value64
    condj = i8.Op2.value64

    template = "j{suffix} {condj}\njmp {jmp}"
    asm = template.format(suffix=i9.get_canon_mnem()[4:], condj=condj, jmp=jmp)
    assembled, _ = ks.asm(asm, addr=i0.ea, as_bytes=True)
    return assembled, 14, (jmp, condj)

@unmutator.register_handler
def condj_handler2(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6E5E220F8 41 54                                         push    r12
    .text:00007FF6E5E220FA 49 BC 6E 5B A7 E6 F6 7F 00 00                 mov     r12, offset unk_7FF6E6A75B6E
    .text:00007FF6E5E22104 4C 87 24 24                                   xchg    r12, [rsp]
    .text:00007FF6E5E22108 52                                            push    rdx
    .text:00007FF6E5E22109 53                                            push    rbx
    .text:00007FF6E5E2210A 48 8B 54 24 10                                mov     rdx, [rsp+10h]
    .text:00007FF6E5E2210F 48 BB 9A 5B A7 E6 F6 7F 00 00                 mov     rbx, offset unk_7FF6E6A75B9A
    .text:00007FF6E5E22119 48 0F 44 D3                                   cmov__  rdx, rbx
    .text:00007FF6E5E2211D 48 89 54 24 10                                mov     [rsp+10h], rdx
    .text:00007FF6E5E22122 5B                                            pop     rbx
    .text:00007FF6E5E22123 5A                                            pop     rdx
    .text:00007FF6E5E22124 C3                                            retn
    """
    global ks
    if len(cur_frame) < 12:
        return None
    
    # this mutation is stupid long, so just checking for mnems *should be* enough (i shouldve done it for the first one)
    i0 = cur_frame[0]; i1 = cur_frame[1]
    i2 = cur_frame[2]; i3 = cur_frame[3]
    i4 = cur_frame[4]; i5 = cur_frame[5]
    i6 = cur_frame[6]; i7 = cur_frame[7]
    i8 = cur_frame[8]; i9 = cur_frame[9]
    i10 = cur_frame[10]; i11 = cur_frame[11]

    if i0.get_canon_mnem() != "push" or i1.get_canon_mnem() != "mov" or \
        i2.get_canon_mnem() != "xchg" or i3.get_canon_mnem() != "push" or \
        i4.get_canon_mnem() != "push" or i5.get_canon_mnem() != "mov" or \
        i6.get_canon_mnem() != "mov" or i7.get_canon_mnem()[:4] != "cmov" or \
        i8.get_canon_mnem() != "mov" or i9.get_canon_mnem() != "pop" or \
        i10.get_canon_mnem() != "pop" or i11.get_canon_mnem() != "retn":
        return None
    
    jmp = i1.Op2.value64
    condj = i6.Op2.value64

    template = "j{suffix} {condj}\njmp {jmp}"
    asm = template.format(suffix=i7.get_canon_mnem()[4:], condj=condj, jmp=jmp)
    assembled, _ = ks.asm(asm, addr=i0.ea, as_bytes=True)
    return assembled, 12, (jmp, condj)

@unmutator.register_handler
def condj_handler3(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FB75728A 57                                            push    rdi
    .text:00007FF6FB75728B 48 BF 95 19 8B FE F6 7F 00 00                 mov     rdi, offset unk_7FF6FE8B1995
    .text:00007FF6FB757295 50                                            push    rax
    .text:00007FF6FB757296 48 8B 44 24 08                                mov     rax, [rsp+8]
    .text:00007FF6FB75729B 48 89 7C 24 08                                mov     [rsp+8], rdi
    .text:00007FF6FB7572A0 48 89 C7                                      mov     rdi, rax
    .text:00007FF6FB7572A3 58                                            pop     rax
    .text:00007FF6FB7572A4 53                                            push    rbx
    .text:00007FF6FB7572A5 50                                            push    rax
    .text:00007FF6FB7572A6 48 8B 5C 24 10                                mov     rbx, [rsp+10h]
    .text:00007FF6FB7572AB 48 B8 F0 5C A7 E6 F6 7F 00 00                 mov     rax, offset unk_7FF6E6A75CF0
    .text:00007FF6FB7572B5 48 0F 45 D8                                   cmov__  rbx, rax
    .text:00007FF6FB7572B9 48 89 5C 24 10                                mov     [rsp+10h], rbx
    .text:00007FF6FB7572BE 58                                            pop     rax
    .text:00007FF6FB7572BF 5B                                            pop     rbx
    .text:00007FF6FB7572C0 C3                                            retn
    """
    global ks
    if len(cur_frame) < 16:
        return None
    
    # another stupid long mutation, only check the mnems again
    i0 = cur_frame[0]; i1 = cur_frame[1]
    i2 = cur_frame[2]; i3 = cur_frame[3]
    i4 = cur_frame[4]; i5 = cur_frame[5]
    i6 = cur_frame[6]; i7 = cur_frame[7]
    i8 = cur_frame[8]; i9 = cur_frame[9]
    i10 = cur_frame[10]; i11 = cur_frame[11]
    i12 = cur_frame[12]; i13 = cur_frame[13]
    i14 = cur_frame[14]; i15 = cur_frame[15]

    if i0.get_canon_mnem() != "push" or i1.get_canon_mnem() != "mov" or \
        i2.get_canon_mnem() != "push" or i3.get_canon_mnem() != "mov" or \
        i4.get_canon_mnem() != "mov" or i5.get_canon_mnem() != "mov" or \
        i6.get_canon_mnem() != "pop" or i7.get_canon_mnem() != "push" or \
        i8.get_canon_mnem() != "push" or i9.get_canon_mnem() != "mov" or \
        i10.get_canon_mnem() != "mov" or i11.get_canon_mnem()[:4] != "cmov" or \
        i12.get_canon_mnem() != "mov" or i13.get_canon_mnem() != "pop" or \
        i14.get_canon_mnem() != "pop" or i15.get_canon_mnem() != "retn":
        return None
    
    jmp = i1.Op2.value64
    condj = i10.Op2.value64

    template = "j{suffix} {condj}\njmp {jmp}"
    asm = template.format(suffix=i11.get_canon_mnem()[4:], condj=condj, jmp=jmp)
    assembled, _ = ks.asm(asm, addr=i0.ea, as_bytes=True)
    return assembled, 16, (jmp, condj)

############################################
############################################
# jmp handlers
############################################
############################################

@unmutator.register_handler
def jmp_handler1(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FB5C7561 57                                            push    rdi
    .text:00007FF6FB5C7562 48 8D 3D A0 EA 25 01                          lea     rdi, sub_7FF6FC826009
    .text:00007FF6FB5C7569 50                                            push    rax
    .text:00007FF6FB5C756A 48 8B 44 24 08                                mov     rax, [rsp+8]
    .text:00007FF6FB5C756F 48 89 7C 24 08                                mov     [rsp+8], rdi
    .text:00007FF6FB5C7574 48 89 C7                                      mov     rdi, rax
    .text:00007FF6FB5C7577 58                                            pop     rax
    .text:00007FF6FB5C7578 C3                                            retn
    """
    global ks
    if len(cur_frame) < 8:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "push" or \
        i0.Op1.type != ida_ua.o_reg:
        return None

    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "lea" or \
        i1.Op1.type != ida_ua.o_reg or \
        i1.Op2.type != ida_ua.o_mem:
        return None

    # 3rd line
    i2 = cur_frame[2]
    if i2.get_canon_mnem() != "push" or \
        i2.Op1.type != ida_ua.o_reg:
        return None

    # 4th line
    i3 = cur_frame[3]
    if i3.get_canon_mnem() != "mov" or \
        i3.Op1.type != ida_ua.o_reg or \
        i3.Op2.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i3.Op2.reg, 8) != "rsp" or \
        SKIP_LESSER_CHECKS:
        return None

    # 5th line
    i4 = cur_frame[4]
    if i4.get_canon_mnem() != "mov" or \
        i4.Op1.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i3.Op2.reg, 8) != "rsp" or \
        SKIP_LESSER_CHECKS or \
        i4.Op2.type != ida_ua.o_reg:
        return None

    # 6th line
    i5 = cur_frame[5]
    if i5.get_canon_mnem() != "mov" or \
        i5.Op1.type != ida_ua.o_reg or \
        i5.Op2.type != ida_ua.o_reg:
        return None

    # 7th line
    i6 = cur_frame[6]
    if i6.get_canon_mnem() != "pop" or \
        SKIP_LESSER_CHECKS:
        return None

    # 8th line
    i7 = cur_frame[7]
    if i7.get_canon_mnem() != "retn":
        return None
    
    jmp_addr = i1.Op2.addr

    template = "jmp {jmp_addr}"
    asm = template.format(jmp_addr=jmp_addr)
    assembled, _ = ks.asm(asm, addr=i0.ea, as_bytes=True)
    return assembled, 8, (jmp_addr,)

@unmutator.register_handler
def jmp_handler2(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FE86EFCD 41 54                                         push    r12
    .text:00007FF6FE86EFCF 4C 8D 25 8F 91 30 00                          lea     r12, loc_7FF6FEB78165
    .text:00007FF6FE86EFD6 FF 34 24                                      push    qword ptr [rsp]
    .text:00007FF6FE86EFD9 4C 89 64 24 08                                mov     [rsp+8], r12
    .text:00007FF6FE86EFDE 41 5C                                         pop     r12
    .text:00007FF6FE86EFE0 C3                                            retn
    """
    global ks
    if len(cur_frame) < 6:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "push" or \
        i0.Op1.type != ida_ua.o_reg:
        return None

    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "lea" or \
        i1.Op1.type != ida_ua.o_reg or \
        i1.Op2.type != ida_ua.o_mem:
        return None
    
    # 3rd line
    i2 = cur_frame[2]
    if i2.get_canon_mnem() != "push" or \
        i2.Op1.type != ida_ua.o_phrase or \
        SKIP_LESSER_CHECKS:
        return None
    
    # 4th line
    i3 = cur_frame[3]
    if i3.get_canon_mnem() != "mov" or \
        i3.Op1.type != ida_ua.o_displ or \
        ida_idp.get_reg_name(i3.Op1.reg, 8) != "rsp" or \
        SKIP_LESSER_CHECKS or \
        i3.Op2.type != ida_ua.o_reg:
        return None
    
    # 5th line
    i4 = cur_frame[4]
    if i4.get_canon_mnem() != "pop" or \
        SKIP_LESSER_CHECKS:
        return None
    
    # 6th line
    i5 = cur_frame[5]
    if i5.get_canon_mnem() != "retn":
        return None

    jmp_addr = i1.Op2.addr

    template = "jmp {jmp_addr}"
    asm = template.format(jmp_addr=jmp_addr)
    assembled, _ = ks.asm(asm, addr=i0.ea, as_bytes=True)
    return assembled, 6, (jmp_addr,)

@unmutator.register_handler
def jmp_handler3(cur_frame: list[ida_ua.insn_t]) -> None | tuple:
    """
    Handles the following case:
    .text:00007FF6FB52883D                 push    rcx
    .text:00007FF6FB52883E                 lea     rcx, unk_7FF6FEC28D04
    .text:00007FF6FB528845                 xchg    rcx, [rsp]
    .text:00007FF6FB528849                 retn
    """
    global ks
    if len(cur_frame) < 4:
        return None
    
    # 1st line
    i0 = cur_frame[0]
    if i0.get_canon_mnem() != "push" or \
        i0.Op1.type != ida_ua.o_reg:
        return None
    
    # 2nd line
    i1 = cur_frame[1]
    if i1.get_canon_mnem() != "lea" or \
        i1.Op1.type != ida_ua.o_reg or \
        i1.Op2.type != ida_ua.o_mem:
        return None
    
    # 3rd line
    i2 = cur_frame[2]
    if i2.get_canon_mnem() != "xchg" or \
        SKIP_LESSER_CHECKS:
        return None
    
    # 4th line
    i3 = cur_frame[3]
    if i3.get_canon_mnem() != "retn":
        return None
    
    jmp_addr = i1.Op2.addr

    template = "jmp {jmp_addr}"
    asm = template.format(jmp_addr=jmp_addr)
    assembled, _ = ks.asm(asm, addr=i0.ea, as_bytes=True)
    return assembled, 4, (jmp_addr,)

############################################
############################################
# MAIN CODE
############################################
############################################

jumps_mnem = {
    "jo","jno","js","jns","je","jz","jne","jnz","jb","jnae","jc","jnb","jae","jnc",
    "jbe","jna","ja","jnbe","jl","jnge","jge","jnl","jle","jng","jg","jnle","jp",
    "jpe","jnp","jpo","jcxz","jecxz",
    "jmp"
}

tainted = set()
analyzed_ranges = []

def analyze_call(ea):
    global func_list, tainted
    FUNC_START = ea

    to_analyze = [FUNC_START]
    while to_analyze:
        cur = to_analyze.pop(0)
        if cur in tainted:
            continue

        tainted.add(cur)
        frame = get_frame(cur)

        start_ea = cur
        end_ea = 0 # dynamically keep track of end_ea so that it ends up ending on a real insn and not nop

        while frame:
            result = unmutator.find_mutation(frame)
            if result is None:
                #print(f"Got normal insn @ {frame[0].ea:#x}")
                insn = frame.pop(0)
                if insn.get_canon_mnem() in jumps_mnem and \
                    insn.Op1.type == ida_ua.o_near:
                    to_analyze.append(insn.Op1.addr)
                elif insn.get_canon_mnem() == "call" and \
                    insn.Op1.type == ida_ua.o_near:
                    func_list.append(insn.Op1.addr)
                end_ea = insn.ea + insn.size
            else:
                unmutated, to_pop, new_addrs = result
                print(f"Found mutated insn @ {frame[0].ea:#x} | {unmutated} {to_pop}")
                
                mutated_len = 0
                for insn in frame[:to_pop]:
                    mutated_len += insn.size
                
                if DO_PATCH:
                    start = frame[0].ea
                    for i, byte in enumerate(unmutated.ljust(mutated_len, b"\x90")):
                        idc.patch_byte(start + i, byte)                

                end_ea = frame[0].ea + len(unmutated)
                frame = frame[to_pop:]
                to_analyze.extend(new_addrs)
        
        analyzed_ranges.append((start_ea, end_ea))

        # assert end_ea != 0
        # if FUNC_START != start_ea: ida_funcs.append_func_tail(FUNC_START, start_ea, end_ea)

func_list = [DEOBF_START]
while func_list:
    ea = func_list.pop(0)
    # ida_funcs.add_func(ea)
    analyze_call(ea)

# undef everything because ida is stupid sometimes so we have to do this
# to get the patched instructions reanalyzed properly
for start_ea, end_ea in analyzed_ranges:
    for ea in range(start_ea, end_ea):
        # delete all code, function tails, and undef any previous func it may be part of
        ida_bytes.del_items(ea)
        while ida_funcs.remove_func_tail(ea, ea):
            pass

        fn = ida_funcs.get_func(ea)
        if fn and fn.start_ea != DEOBF_START:
            ida_funcs.del_func(fn.start_ea)

############################################
############################################
# reanalyze everything
############################################
############################################

tainted = set()
func_list = [DEOBF_START]

def fix_funcs(func_ea):
    global tainted, func_list

    to_analyze = [func_ea]
    while to_analyze:
        cur_ea = to_analyze.pop(0)
        if cur_ea in tainted:
            continue

        tainted.add(cur_ea)
        frame = get_frame(cur_ea)
        for insn in frame:
            mnem = insn.get_canon_mnem()
            if mnem in jumps_mnem and \
                insn.Op1.type == ida_ua.o_near:
                to_analyze.append(insn.Op1.addr)
            elif mnem == "call" and \
                insn.Op1.type == ida_ua.o_near:
                func_list.append(insn.Op1.addr)
            
            # its possible we set a chunk too early when there's a part behind it that should be a part of it
            # ida wont let you overlap chunks, so you have to remove the original one
            fchunk = ida_funcs.get_fchunk(insn.ea)
            if fchunk is not None and \
                fchunk.owner == func_ea and \
                fchunk.start_ea > cur_ea:
                while ida_funcs.remove_func_tail(insn.ea, insn.ea):
                    pass
        
        if cur_ea != func_ea:
            ida_funcs.append_func_tail(func_ea, cur_ea, frame[-1].ea + frame[-1].size)



while func_list:
    ea = func_list.pop(0)
    ida_funcs.add_func(ea)
    fix_funcs(ea)


print("Done!")
