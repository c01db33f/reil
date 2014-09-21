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

from reil.x86.utilities import *


def _memory_address(ctx, i, opnd):

    address = None

    if opnd.mem.disp != 0 and opnd.mem.base == 0:

        address = imm(opnd.mem.disp & mask(ctx.word_size), ctx.word_size)

    elif opnd.mem.disp == 0 and opnd.mem.base != 0:

        address = ctx.registers[opnd.mem.base]

    elif opnd.mem.disp != 0 and opnd.mem.base != 0:

        base = ctx.registers[opnd.mem.base]
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

    if i.segment != 0:

        tmp0 = ctx.tmp(ctx.word_size * 2)
        prev_address = address
        address = ctx.tmp(ctx.word_size)

        ctx.emit(  add_  (prev_address,
                          ctx.registers[i.segment],
                          tmp0))

        ctx.emit(  and_  (tmp0,
                          imm(mask(ctx.word_size), ctx.word_size * 2),
                          address))

    if opnd.mem.index != 0:

        index = ctx.registers[opnd.mem.index]
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


def _memory_size(ctx, i, opnd):

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


def _get_register(ctx, i, opnd):
    # full native registers
    if opnd.reg in ctx.registers:
        return ctx.registers[opnd.reg]

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

    if opnd.reg in low_bytes:
        byte_reg = ctx.tmp(8)

        ctx.emit(  str_  (low_bytes[opnd.reg], byte_reg))

        return byte_reg

    # 8-bit high parts
    high_bytes = {
        capstone.x86.X86_REG_AH:ctx.accumulator,
        capstone.x86.X86_REG_BH:ctx.base,
        capstone.x86.X86_REG_CH:ctx.counter,
        capstone.x86.X86_REG_DH:ctx.data
    }

    if opnd.reg in high_bytes:

        full_reg = high_bytes[opnd.reg]
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

    if opnd.reg in low_words:
        word_reg = ctx.tmp(16)

        ctx.emit(  str_  (low_words[opnd.reg], word_reg))

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

    if opnd.reg in low_dwords:
        dword_reg = ctx.tmp(32)

        ctx.emit(  str_  (low_dwords[opnd.reg], dword_reg))

        return dword_reg

    raise TranslationError('Unsupported register!')


def _get_immediate(ctx, i, opnd, size=0):

    if size == 0:
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

    value = ctx.tmp(_memory_size(ctx, i, opnd))

    ctx.emit(  ldm_  (address, value))

    return value


def get_address(ctx, i, index):
    opnd = i.operands[index]

    address = _memory_address(ctx, i, opnd)

    return address


def get(ctx, i, index, size=0):

    opnd = i.operands[index]

    if opnd.type == capstone.x86.X86_OP_REG:
        return _get_register(ctx, i, opnd)

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
        return _get_register(ctx, i, opnd).size

    elif opnd.type == capstone.x86.X86_OP_IMM:
        return _get_immediate(ctx, i, opnd, size).size

    elif opnd.type == capstone.x86.X86_OP_MEM:
        return _memory_size(ctx, i, opnd)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def _set_register(ctx, i, opnd, value, clear=False, sign_extend=False):

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

    # full native registers
    if opnd.reg in ctx.registers:
        reg = ctx.registers[opnd.reg]
        set_mask = imm(mask(reg.size), reg.size)

    # 8-bit low parts
    elif opnd.reg in low_bytes:
        reg = low_bytes[opnd.reg]
        set_mask = imm(~mask(8), reg.size)

    # 8-bit high parts
    elif opnd.reg in high_bytes:
        reg = high_bytes[opnd.reg]

        prev_value = value
        value = ctx.tmp(reg.size)
        tmp0 = ctx.tmp(reg.size)
        tmp1 = ctx.tmp(reg.size)

        ctx.emit(  and_  (reg, imm(mask(reg.size) ^ 0xff00, reg.size), tmp0))
        ctx.emit(  str_  (prev_value, tmp1))
        ctx.emit(  lshl_ (tmp1, imm(8, 8), tmp1))
        ctx.emit(  or_   (tmp0, tmp1, value))

    # 16-bit low parts
    elif opnd.reg in low_words:
        reg = low_words[opnd.reg]
        set_mask = imm(~mask(16), reg.size)

    # 32-bit low parts
    elif opnd.reg in low_dwords:
        reg = low_dwords[opnd.reg]
        set_mask = imm(~mask(32), reg.size)

    else:
        raise TranslationError('Unsupported register!')

    if value.size > reg.size:
        prev_value = value
        value = ctx.tmp(reg.size)

        ctx.emit(  str_  (prev_value, value))

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

            ctx.emit(  and_  (reg, set_mask, tmp0))
            ctx.emit(  or_   (tmp0, prev_value, value))

    ctx.emit(  str_  (value, reg))


def _set_memory(ctx, i, opnd, value):

    address = _memory_address(ctx, i, opnd)
    write_size = _memory_size(ctx, i, opnd)

    if value.size > write_size:

        prev_value = value
        value = ctx.tmp(write_size)

        ctx.emit(  str_  (prev_value, value))

    ctx.emit(  stm_  (value, address))


def set(ctx, i, index, value, clear=False, sign_extend=False):

    opnd = i.operands[index]

    if opnd.type == capstone.x86.X86_OP_REG:
        return _set_register(ctx, i, opnd, value, clear, sign_extend)

    elif opnd.type == capstone.x86.X86_OP_MEM:
        return _set_memory(ctx, i, opnd, value)

    else:
        raise TranslationError(
            'Unsupported operand type!')