# -*- coding: utf-8 -*-

#    Copyright 2014 Mark Brand - c01db33f (at) gmail.com
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""reil.x86.operands - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file contains helpers for reading and writing instruction
operands.
"""

import capstone

from reil.error import *
from reil.shorthand import *
from reil.utilities import *

from reil.x86.utilities import *


def _reg_id_from_name(name):
    register_lookup = {
        'al':capstone.x86.X86_REG_AL,
        'ah':capstone.x86.X86_REG_AH,
        'bl':capstone.x86.X86_REG_BL,
        'bh':capstone.x86.X86_REG_BH,
        'cl':capstone.x86.X86_REG_CL,
        'ch':capstone.x86.X86_REG_CH,
        'dl':capstone.x86.X86_REG_DL,
        'dh':capstone.x86.X86_REG_DH,
        'sil':capstone.x86.X86_REG_SIL,
        'dil':capstone.x86.X86_REG_DIL,
        'bpl':capstone.x86.X86_REG_BPL,
        'spl':capstone.x86.X86_REG_SPL,
        'r8b':capstone.x86.X86_REG_R8B,
        'r9b':capstone.x86.X86_REG_R9B,
        'r10b':capstone.x86.X86_REG_R10B,
        'r11b':capstone.x86.X86_REG_R11B,
        'r12b':capstone.x86.X86_REG_R12B,
        'r13b':capstone.x86.X86_REG_R13B,
        'r14b':capstone.x86.X86_REG_R14B,
        'r15b':capstone.x86.X86_REG_R15B,

        'ax':capstone.x86.X86_REG_AX,
        'bx':capstone.x86.X86_REG_BX,
        'cx':capstone.x86.X86_REG_CX,
        'dx':capstone.x86.X86_REG_DX,
        'si':capstone.x86.X86_REG_SI,
        'di':capstone.x86.X86_REG_DI,
        'bp':capstone.x86.X86_REG_BP,
        'sp':capstone.x86.X86_REG_SP,
        'r8w':capstone.x86.X86_REG_R8W,
        'r9w':capstone.x86.X86_REG_R9W,
        'r10w':capstone.x86.X86_REG_R10W,
        'r11w':capstone.x86.X86_REG_R11W,
        'r12w':capstone.x86.X86_REG_R12W,
        'r13w':capstone.x86.X86_REG_R13W,
        'r14w':capstone.x86.X86_REG_R14W,
        'r15w':capstone.x86.X86_REG_R15W,

        'eax':capstone.x86.X86_REG_EAX,
        'ebx':capstone.x86.X86_REG_EBX,
        'ecx':capstone.x86.X86_REG_ECX,
        'edx':capstone.x86.X86_REG_EDX,
        'esi':capstone.x86.X86_REG_ESI,
        'edi':capstone.x86.X86_REG_EDI,
        'ebp':capstone.x86.X86_REG_EBP,
        'esp':capstone.x86.X86_REG_ESP,
        'r8d':capstone.x86.X86_REG_R8,
        'r9d':capstone.x86.X86_REG_R9,
        'r10d':capstone.x86.X86_REG_R10D,
        'r11d':capstone.x86.X86_REG_R11D,
        'r12d':capstone.x86.X86_REG_R12D,
        'r13d':capstone.x86.X86_REG_R13D,
        'r14d':capstone.x86.X86_REG_R14D,
        'r15d':capstone.x86.X86_REG_R15D,

        'rax':capstone.x86.X86_REG_AX,
        'rbx':capstone.x86.X86_REG_BX,
        'rcx':capstone.x86.X86_REG_CX,
        'rdx':capstone.x86.X86_REG_DX,
        'rsi':capstone.x86.X86_REG_SI,
        'rdi':capstone.x86.X86_REG_DI,
        'rbp':capstone.x86.X86_REG_BP,
        'rsp':capstone.x86.X86_REG_SP,
        'r8':capstone.x86.X86_REG_R8,
        'r9':capstone.x86.X86_REG_R9,
        'r10':capstone.x86.X86_REG_R10,
        'r11':capstone.x86.X86_REG_R11,
        'r12':capstone.x86.X86_REG_R12,
        'r13':capstone.x86.X86_REG_R13,
        'r14':capstone.x86.X86_REG_R14,
        'r15':capstone.x86.X86_REG_R15,
        'rip':capstone.x86.X86_REG_RIP
    }

    if name not in register_lookup:
        raise TranslationError('Invalid Register {}'.format(name))

    return register_lookup[name]


def _memory_address(ctx, i, opnd):

    address = None

    if opnd.mem.disp != 0 and opnd.mem.base == 0:

        address = imm(opnd.mem.disp & mask(ctx.word_size), ctx.word_size)

    elif opnd.mem.disp == 0 and opnd.mem.base != 0:

        address = _get_register(ctx, i, opnd.mem.base)

    elif opnd.mem.disp != 0 and opnd.mem.base != 0:

        base = _get_register(ctx, i, opnd.mem.base)
        tmp0 = ctx.tmp(ctx.word_size * 2)
        address = ctx.tmp(ctx.word_size)

        ctx.emit(  add_  (base,
                          imm(opnd.mem.disp & mask(ctx.word_size), ctx.word_size),
                          tmp0))

        ctx.emit(  and_  (tmp0,
                          imm(mask(ctx.word_size), ctx.word_size * 2),
                          address))
    else:
        address = imm(0, ctx.word_size)

    if opnd.mem.segment != 0:

        tmp0 = ctx.tmp(ctx.word_size * 2)
        prev_address = address
        address = ctx.tmp(ctx.word_size)

        ctx.emit(  add_  (prev_address,
                          ctx.registers[opnd.mem.segment],
                          tmp0))

        ctx.emit(  and_  (tmp0,
                          imm(mask(ctx.word_size), ctx.word_size * 2),
                          address))

    if opnd.mem.index != 0:

        index = _get_register(ctx, i, opnd.mem.index)
        tmp0 = ctx.tmp(ctx.word_size * 2)
        tmp1 = ctx.tmp(ctx.word_size)
        tmp2 = ctx.tmp(ctx.word_size * 2)
        prev_address = address
        address = ctx.tmp(ctx.word_size)

        ctx.emit(  mul_  (index,
                          imm(opnd.mem.scale, ctx.word_size),
                          tmp0))

        ctx.emit(  and_  (tmp0,
                          imm(mask(ctx.word_size), ctx.word_size * 2),
                          tmp1))

        ctx.emit(  add_  (tmp1, prev_address, tmp2))
        ctx.emit(  and_  (tmp2,
                          imm(mask(ctx.word_size), ctx.word_size * 2),
                          address))

    return address


def _get_memory_size(ctx, i, opnd):

    if 'byte' in i.op_str:
        return 8

    elif 'dword' in i.op_str:
        return 32

    elif 'qword' in i.op_str:
        return 64

    elif 'xmmword' in i.op_str:
        return 128

    elif 'word' in i.op_str:
        return 16

    else:
        return ctx.word_size


def _get_register(ctx, i, reg):
    # we need to handle rip first to shortcut native register handling.
    if reg == capstone.x86.X86_REG_RIP and not ctx.use_rip:
        qword_reg = ctx.tmp(64)

        ctx.emit(  str_  (imm(i.address + i.size, 64), qword_reg))

        return qword_reg

    # full native registers
    if reg in ctx.registers:
        return ctx.registers[reg]

    # 8-bit low parts
    low_bytes = {
        capstone.x86.X86_REG_AL:ctx.accumulator,
        capstone.x86.X86_REG_BL:ctx.base,
        capstone.x86.X86_REG_CL:ctx.counter,
        capstone.x86.X86_REG_DL:ctx.data,
        capstone.x86.X86_REG_SIL:ctx.source,
        capstone.x86.X86_REG_DIL:ctx.destination,
        capstone.x86.X86_REG_BPL:ctx.frame_ptr,
        capstone.x86.X86_REG_SPL:ctx.stack_ptr,
        capstone.x86.X86_REG_R8B:r('r8', 64),
        capstone.x86.X86_REG_R9B:r('r9', 64),
        capstone.x86.X86_REG_R10B:r('r10', 64),
        capstone.x86.X86_REG_R11B:r('r11', 64),
        capstone.x86.X86_REG_R12B:r('r12', 64),
        capstone.x86.X86_REG_R13B:r('r13', 64),
        capstone.x86.X86_REG_R14B:r('r14', 64),
        capstone.x86.X86_REG_R15B:r('r15', 64),
    }

    if reg in low_bytes:
        byte_reg = ctx.tmp(8)

        ctx.emit(  str_  (low_bytes[reg], byte_reg))

        return byte_reg

    # 8-bit high parts
    high_bytes = {
        capstone.x86.X86_REG_AH:ctx.accumulator,
        capstone.x86.X86_REG_BH:ctx.base,
        capstone.x86.X86_REG_CH:ctx.counter,
        capstone.x86.X86_REG_DH:ctx.data
    }

    if reg in high_bytes:

        full_reg = high_bytes[reg]
        word_reg = ctx.tmp(16)
        byte_reg = ctx.tmp(8)

        ctx.emit(  str_  (full_reg, word_reg))
        ctx.emit(  lshr_ (word_reg, imm(8, 8), byte_reg))

        return byte_reg

    # 16-byte low parts
    low_words = {
        capstone.x86.X86_REG_AX:ctx.accumulator,
        capstone.x86.X86_REG_BX:ctx.base,
        capstone.x86.X86_REG_CX:ctx.counter,
        capstone.x86.X86_REG_DX:ctx.data,
        capstone.x86.X86_REG_SI:ctx.source,
        capstone.x86.X86_REG_DI:ctx.destination,
        capstone.x86.X86_REG_BP:ctx.frame_ptr,
        capstone.x86.X86_REG_SP:ctx.stack_ptr,
        capstone.x86.X86_REG_R8W:r('r8', 64),
        capstone.x86.X86_REG_R9W:r('r9', 64),
        capstone.x86.X86_REG_R10W:r('r10', 64),
        capstone.x86.X86_REG_R11W:r('r11', 64),
        capstone.x86.X86_REG_R12W:r('r12', 64),
        capstone.x86.X86_REG_R13W:r('r13', 64),
        capstone.x86.X86_REG_R14W:r('r14', 64),
        capstone.x86.X86_REG_R15W:r('r15', 64),
    }

    if reg in low_words:
        word_reg = ctx.tmp(16)

        ctx.emit(  str_  (low_words[reg], word_reg))

        return word_reg

    # 32-byte low parts
    low_dwords = {
        capstone.x86.X86_REG_EAX:ctx.accumulator,
        capstone.x86.X86_REG_EBX:ctx.base,
        capstone.x86.X86_REG_ECX:ctx.counter,
        capstone.x86.X86_REG_EDX:ctx.data,
        capstone.x86.X86_REG_ESI:ctx.source,
        capstone.x86.X86_REG_EDI:ctx.destination,
        capstone.x86.X86_REG_EBP:ctx.frame_ptr,
        capstone.x86.X86_REG_ESP:ctx.stack_ptr,
        capstone.x86.X86_REG_R8D:r('r8', 64),
        capstone.x86.X86_REG_R9D:r('r9', 64),
        capstone.x86.X86_REG_R10D:r('r10', 64),
        capstone.x86.X86_REG_R11D:r('r11', 64),
        capstone.x86.X86_REG_R12D:r('r12', 64),
        capstone.x86.X86_REG_R13D:r('r13', 64),
        capstone.x86.X86_REG_R14D:r('r14', 64),
        capstone.x86.X86_REG_R15D:r('r15', 64),
    }

    if reg in low_dwords:
        dword_reg = ctx.tmp(32)

        ctx.emit(  str_  (low_dwords[reg], dword_reg))

        return dword_reg

    raise TranslationError('Unsupported register!')


def _get_register_size(ctx, i, reg_id):
    # full native registers
    if reg_id in ctx.registers:
        return ctx.registers[reg_id].size

    # 8-bit low parts
    low_bytes = [
        capstone.x86.X86_REG_AL,
        capstone.x86.X86_REG_BL,
        capstone.x86.X86_REG_CL,
        capstone.x86.X86_REG_DL,
        capstone.x86.X86_REG_SIL,
        capstone.x86.X86_REG_DIL,
        capstone.x86.X86_REG_BPL,
        capstone.x86.X86_REG_SPL,
        capstone.x86.X86_REG_R8B,
        capstone.x86.X86_REG_R9B,
        capstone.x86.X86_REG_R10B,
        capstone.x86.X86_REG_R11B,
        capstone.x86.X86_REG_R12B,
        capstone.x86.X86_REG_R13B,
        capstone.x86.X86_REG_R14B,
        capstone.x86.X86_REG_R15B,
    ]

    if reg_id in low_bytes:
        return 8

    # 8-bit high parts
    high_bytes = [
        capstone.x86.X86_REG_AH,
        capstone.x86.X86_REG_BH,
        capstone.x86.X86_REG_CH,
        capstone.x86.X86_REG_DH
    ]

    if reg_id in high_bytes:
        return 8

    # 16-byte low parts
    low_words = {
        capstone.x86.X86_REG_AX,
        capstone.x86.X86_REG_BX,
        capstone.x86.X86_REG_CX,
        capstone.x86.X86_REG_DX,
        capstone.x86.X86_REG_SI,
        capstone.x86.X86_REG_DI,
        capstone.x86.X86_REG_BP,
        capstone.x86.X86_REG_SP,
        capstone.x86.X86_REG_R8W,
        capstone.x86.X86_REG_R9W,
        capstone.x86.X86_REG_R10W,
        capstone.x86.X86_REG_R11W,
        capstone.x86.X86_REG_R12W,
        capstone.x86.X86_REG_R13W,
        capstone.x86.X86_REG_R14W,
        capstone.x86.X86_REG_R15W,
    }

    if reg_id in low_words:
        return 16

    # 32-byte low parts
    low_dwords = {
        capstone.x86.X86_REG_EAX,
        capstone.x86.X86_REG_EBX,
        capstone.x86.X86_REG_ECX,
        capstone.x86.X86_REG_EDX,
        capstone.x86.X86_REG_ESI,
        capstone.x86.X86_REG_EDI,
        capstone.x86.X86_REG_EBP,
        capstone.x86.X86_REG_ESP,
        capstone.x86.X86_REG_R8D,
        capstone.x86.X86_REG_R9D,
        capstone.x86.X86_REG_R10D,
        capstone.x86.X86_REG_R11D,
        capstone.x86.X86_REG_R12D,
        capstone.x86.X86_REG_R13D,
        capstone.x86.X86_REG_R14D,
        capstone.x86.X86_REG_R15D,
    }

    if reg_id in low_dwords:
        return 32

    if reg_id is capstone.x86.X86_REG_RIP:
        return 64

    raise TranslationError('Unsupported register!')


def _get_immediate(ctx, i, opnd, size=0):

    if size == 0:
        # TODO: This does not work. How to do this better?

        # maybe all immediates should be the minimum possible size to
        # represent them?

        bs = opnd.imm.bit_length()

        if bs == 0:
            size = ctx.word_size
        else:
            for i in [8, 16, 32, 64, 128]:
                if bs < i:
                    size = i
                    break

    return imm(opnd.imm, size)


def _get_memory(ctx, i, opnd):

    address = _memory_address(ctx, i, opnd)

    value = ctx.tmp(_get_memory_size(ctx, i, opnd))

    ctx.emit(  ldm_  (address, value))

    return value


def get_address(ctx, i, index):
    opnd = i.operands[index]

    address = _memory_address(ctx, i, opnd)

    return address


def get_register(ctx, i, name):
    reg_id = _reg_id_from_name(name)

    return _get_register(ctx, i, reg_id)


def get(ctx, i, index, size=0):

    opnd = i.operands[index]

    if opnd.type == capstone.x86.X86_OP_REG:
        return _get_register(ctx, i, opnd.reg)

    elif opnd.type == capstone.x86.X86_OP_IMM:
        return _get_immediate(ctx, i, opnd, size)

    elif opnd.type == capstone.x86.X86_OP_MEM:
        return _get_memory(ctx, i, opnd)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def get_size(ctx, i, index, size=0):

    opnd = i.operands[index]

    if opnd.type == capstone.x86.X86_OP_REG:
        return _get_register_size(ctx, i, opnd.reg)

    elif opnd.type == capstone.x86.X86_OP_IMM:
        return _get_immediate(ctx, i, opnd, size).size

    elif opnd.type == capstone.x86.X86_OP_MEM:
        return _get_memory_size(ctx, i, opnd)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def is_register(ctx, i, index):
    return i.operands[index].type == capstone.x86.X86_OP_REG


def is_immediate(ctx, i, index):
    return i.operands[index].type == capstone.x86.X86_OP_IMM


def is_memory(ctx, i, index):
    return i.operands[index].type == capstone.x86.X86_OP_MEM


def _set_register(ctx, i, reg_id, value, clear=False, sign_extend=False):

    low_bytes = {
        capstone.x86.X86_REG_AL:ctx.accumulator,
        capstone.x86.X86_REG_BL:ctx.base,
        capstone.x86.X86_REG_CL:ctx.counter,
        capstone.x86.X86_REG_DL:ctx.data,
        capstone.x86.X86_REG_SIL:ctx.source,
        capstone.x86.X86_REG_DIL:ctx.destination,
        capstone.x86.X86_REG_BPL:ctx.frame_ptr,
        capstone.x86.X86_REG_SPL:ctx.stack_ptr,
        capstone.x86.X86_REG_R8B:r('r8', 64),
        capstone.x86.X86_REG_R9B:r('r9', 64),
        capstone.x86.X86_REG_R10B:r('r10', 64),
        capstone.x86.X86_REG_R11B:r('r11', 64),
        capstone.x86.X86_REG_R12B:r('r12', 64),
        capstone.x86.X86_REG_R13B:r('r13', 64),
        capstone.x86.X86_REG_R14B:r('r14', 64),
        capstone.x86.X86_REG_R15B:r('r15', 64),
    }

    high_bytes = {
        capstone.x86.X86_REG_AH:ctx.accumulator,
        capstone.x86.X86_REG_BH:ctx.base,
        capstone.x86.X86_REG_CH:ctx.counter,
        capstone.x86.X86_REG_DH:ctx.data
    }

    low_words = {
        capstone.x86.X86_REG_AX:ctx.accumulator,
        capstone.x86.X86_REG_BX:ctx.base,
        capstone.x86.X86_REG_CX:ctx.counter,
        capstone.x86.X86_REG_DX:ctx.data,
        capstone.x86.X86_REG_SI:ctx.source,
        capstone.x86.X86_REG_DI:ctx.destination,
        capstone.x86.X86_REG_BP:ctx.frame_ptr,
        capstone.x86.X86_REG_SP:ctx.stack_ptr,
        capstone.x86.X86_REG_R8W:r('r8', 64),
        capstone.x86.X86_REG_R9W:r('r9', 64),
        capstone.x86.X86_REG_R10W:r('r10', 64),
        capstone.x86.X86_REG_R11W:r('r11', 64),
        capstone.x86.X86_REG_R12W:r('r12', 64),
        capstone.x86.X86_REG_R13W:r('r13', 64),
        capstone.x86.X86_REG_R14W:r('r14', 64),
        capstone.x86.X86_REG_R15W:r('r15', 64),
    }

    low_dwords = {
        capstone.x86.X86_REG_EAX:ctx.accumulator,
        capstone.x86.X86_REG_EBX:ctx.base,
        capstone.x86.X86_REG_ECX:ctx.counter,
        capstone.x86.X86_REG_EDX:ctx.data,
        capstone.x86.X86_REG_ESI:ctx.source,
        capstone.x86.X86_REG_EDI:ctx.destination,
        capstone.x86.X86_REG_EBP:ctx.frame_ptr,
        capstone.x86.X86_REG_ESP:ctx.stack_ptr,
        capstone.x86.X86_REG_R8D:r('r8', 64),
        capstone.x86.X86_REG_R9D:r('r9', 64),
        capstone.x86.X86_REG_R10D:r('r10', 64),
        capstone.x86.X86_REG_R11D:r('r11', 64),
        capstone.x86.X86_REG_R12D:r('r12', 64),
        capstone.x86.X86_REG_R13D:r('r13', 64),
        capstone.x86.X86_REG_R14D:r('r14', 64),
        capstone.x86.X86_REG_R15D:r('r15', 64),
    }

    sse_regs = {
        capstone.x86.X86_REG_XMM0:r('xmm0', 128),
        capstone.x86.X86_REG_XMM1:r('xmm1', 128),
        capstone.x86.X86_REG_XMM2:r('xmm2', 128),
        capstone.x86.X86_REG_XMM3:r('xmm3', 128),
        capstone.x86.X86_REG_XMM4:r('xmm4', 128),
        capstone.x86.X86_REG_XMM5:r('xmm5', 128),
        capstone.x86.X86_REG_XMM6:r('xmm6', 128),
        capstone.x86.X86_REG_XMM7:r('xmm7', 128),
        capstone.x86.X86_REG_XMM8:r('xmm8', 128),
        capstone.x86.X86_REG_XMM9:r('xmm9', 128),
        capstone.x86.X86_REG_XMM10:r('xmm10', 128),
        capstone.x86.X86_REG_XMM11:r('xmm11', 128),
        capstone.x86.X86_REG_XMM12:r('xmm12', 128),
        capstone.x86.X86_REG_XMM13:r('xmm13', 128),
        capstone.x86.X86_REG_XMM14:r('xmm14', 128),
        capstone.x86.X86_REG_XMM15:r('xmm15', 128),
    }

    def truncate_value(value, size):

        if value.size > size:
            prev_value = value
            value = ctx.tmp(size)
            ctx.emit(  str_  (prev_value, value))

        return value

    # full native registers
    if reg_id in ctx.registers:
        reg = ctx.registers[reg_id]
        set_mask = imm(mask(reg.size), reg.size)

    # 8-bit low parts
    elif reg_id in low_bytes:
        reg = low_bytes[reg_id]
        set_mask = imm(~mask(8), reg.size)
        value = truncate_value(value, 8)

    # 8-bit high parts
    elif reg_id in high_bytes:
        reg = high_bytes[reg_id]
        value = truncate_value(value, 8)

        prev_value = value
        value = ctx.tmp(reg.size)
        tmp0 = ctx.tmp(reg.size)
        tmp1 = ctx.tmp(reg.size)

        ctx.emit(  and_  (reg, imm(mask(reg.size) ^ 0xff00, reg.size), tmp0))
        ctx.emit(  str_  (prev_value, tmp1))
        ctx.emit(  lshl_ (tmp1, imm(8, 8), tmp1))
        ctx.emit(  or_   (tmp0, tmp1, value))

    # 16-bit low parts
    elif reg_id in low_words:
        reg = low_words[reg_id]
        set_mask = imm(~mask(16), reg.size)
        value = truncate_value(value, 16)

    # 32-bit low parts
    elif reg_id in low_dwords:
        # NB: this code is only reached in x86_64 mode.

        # CF: Intel Manual... 32-bit operands generate a 32-bit result,
        # zero-extended to a 64-bit result in the destination register.

        reg = low_dwords[reg_id]
        set_mask = imm(mask(64), reg.size)
        value = truncate_value(value, 32)
        clear = True

    else:
        raise TranslationError('Unsupported register!')

    if reg_id in sse_regs:
      # NB: We make the default behaviour for setting a smaller value to an SSE
      # register to zero-extend. Code in SSE implementation will have to expect
      # this... But it makes implementation of the memory moves for SSE simpler
      sign_extend = False
      clear = True

    if value.size > reg.size:
        value = truncate_value(value, reg.size)

    elif value.size < reg.size:
        prev_value = value
        value = ctx.tmp(reg.size)

        if clear:
            if sign_extend:
                ctx.emit(  sex_  (prev_value, value))
            else:
                ctx.emit(  str_  (prev_value, value))
        else:
            tmp0 = ctx.tmp(reg.size)

            ctx.emit(  str_  (prev_value, value))
            ctx.emit(  and_  (reg, set_mask, tmp0))
            ctx.emit(  or_   (tmp0, value, value))

    ctx.emit(  str_  (value, reg))


def _set_memory(ctx, i, opnd, value):

    address = _memory_address(ctx, i, opnd)
    write_size = _get_memory_size(ctx, i, opnd)

    if value.size > write_size:

        prev_value = value
        value = ctx.tmp(write_size)

        ctx.emit(  str_  (prev_value, value))

    ctx.emit(  stm_  (value, address))


def set(ctx, i, index, value, clear=False, sign_extend=False):

    opnd = i.operands[index]

    if opnd.type == capstone.x86.X86_OP_REG:
        return _set_register(ctx, i, opnd.reg, value, clear, sign_extend)

    elif opnd.type == capstone.x86.X86_OP_MEM:
        return _set_memory(ctx, i, opnd, value)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def set_register(ctx, i, name, value, clear=False, sign_extend=False):
    reg_id = _reg_id_from_name(name)

    return _set_register(ctx, i, reg_id, value, clear, sign_extend)


def _undef_register(ctx, i, reg_id, clear=False, sign_extend=False):

    low_bytes = {
        capstone.x86.X86_REG_AL:ctx.accumulator,
        capstone.x86.X86_REG_BL:ctx.base,
        capstone.x86.X86_REG_CL:ctx.counter,
        capstone.x86.X86_REG_DL:ctx.data,
        capstone.x86.X86_REG_SIL:ctx.source,
        capstone.x86.X86_REG_DIL:ctx.destination,
        capstone.x86.X86_REG_BPL:ctx.frame_ptr,
        capstone.x86.X86_REG_SPL:ctx.stack_ptr,
        capstone.x86.X86_REG_R8B:r('r8', 64),
        capstone.x86.X86_REG_R9B:r('r9', 64),
        capstone.x86.X86_REG_R10B:r('r10', 64),
        capstone.x86.X86_REG_R11B:r('r11', 64),
        capstone.x86.X86_REG_R12B:r('r12', 64),
        capstone.x86.X86_REG_R13B:r('r13', 64),
        capstone.x86.X86_REG_R14B:r('r14', 64),
        capstone.x86.X86_REG_R15B:r('r15', 64),
    }

    high_bytes = {
        capstone.x86.X86_REG_AH:ctx.accumulator,
        capstone.x86.X86_REG_BH:ctx.base,
        capstone.x86.X86_REG_CH:ctx.counter,
        capstone.x86.X86_REG_DH:ctx.data
    }

    low_words = {
        capstone.x86.X86_REG_AX:ctx.accumulator,
        capstone.x86.X86_REG_BX:ctx.base,
        capstone.x86.X86_REG_CX:ctx.counter,
        capstone.x86.X86_REG_DX:ctx.data,
        capstone.x86.X86_REG_SI:ctx.source,
        capstone.x86.X86_REG_DI:ctx.destination,
        capstone.x86.X86_REG_BP:ctx.frame_ptr,
        capstone.x86.X86_REG_SP:ctx.stack_ptr,
        capstone.x86.X86_REG_R8W:r('r8', 64),
        capstone.x86.X86_REG_R9W:r('r9', 64),
        capstone.x86.X86_REG_R10W:r('r10', 64),
        capstone.x86.X86_REG_R11W:r('r11', 64),
        capstone.x86.X86_REG_R12W:r('r12', 64),
        capstone.x86.X86_REG_R13W:r('r13', 64),
        capstone.x86.X86_REG_R14W:r('r14', 64),
        capstone.x86.X86_REG_R15W:r('r15', 64),
    }

    low_dwords = {
        capstone.x86.X86_REG_EAX:ctx.accumulator,
        capstone.x86.X86_REG_EBX:ctx.base,
        capstone.x86.X86_REG_ECX:ctx.counter,
        capstone.x86.X86_REG_EDX:ctx.data,
        capstone.x86.X86_REG_ESI:ctx.source,
        capstone.x86.X86_REG_EDI:ctx.destination,
        capstone.x86.X86_REG_EBP:ctx.frame_ptr,
        capstone.x86.X86_REG_ESP:ctx.stack_ptr,
        capstone.x86.X86_REG_R8D:r('r8', 64),
        capstone.x86.X86_REG_R9D:r('r9', 64),
        capstone.x86.X86_REG_R10D:r('r10', 64),
        capstone.x86.X86_REG_R11D:r('r11', 64),
        capstone.x86.X86_REG_R12D:r('r12', 64),
        capstone.x86.X86_REG_R13D:r('r13', 64),
        capstone.x86.X86_REG_R14D:r('r14', 64),
        capstone.x86.X86_REG_R15D:r('r15', 64),
    }

    # TODO: this is not really correct, since we always explode the whole
    # register, but we don't really have support for anything else...

    # full native registers
    if reg_id in ctx.registers:
        reg = ctx.registers[reg_id]

    # 8-bit low parts
    elif reg_id in low_bytes:
        reg = low_bytes[reg_id]

    # 8-bit high parts
    elif reg_id in high_bytes:
        reg = high_bytes[reg_id]

    # 16-bit low parts
    elif reg_id in low_words:
        reg = low_words[reg_id]

    # 32-bit low parts
    elif reg_id in low_dwords:
        reg = low_dwords[reg_id]

    else:
        raise TranslationError('Unsupported register!')

    ctx.emit(  undef_  (reg))


def undefine(ctx, i, index):

    opnd = i.operands[index]

    if opnd.type == capstone.x86.X86_OP_REG:
        _undef_register(ctx, i, opnd.reg)

    else:
        raise TranslationError('Can only call operand.undefine on a register operand')
