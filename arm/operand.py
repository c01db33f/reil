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


def _reg_id_from_name(name):
    register_lookup = {
        'r0':  capstone.arm.ARM_REG_R0,
        'r1':  capstone.arm.ARM_REG_R1,
        'r2':  capstone.arm.ARM_REG_R2,
        'r3':  capstone.arm.ARM_REG_R3,
        'r4':  capstone.arm.ARM_REG_R4,
        'r5':  capstone.arm.ARM_REG_R5,
        'r6':  capstone.arm.ARM_REG_R6,
        'r7':  capstone.arm.ARM_REG_R7,
        'r8':  capstone.arm.ARM_REG_R8,
        'r9':  capstone.arm.ARM_REG_R9,
        'r10': capstone.arm.ARM_REG_R10,
        'r11': capstone.arm.ARM_REG_R11,
        'sp':  capstone.arm.ARM_REG_R13,
        'lr':  capstone.arm.ARM_REG_R14,
        'pc':  capstone.arm.ARM_REG_R15,
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

    return address


def _get_memory_size(ctx, i, opnd):
    # TODO: how to get this...
    return 32

def _get_register(ctx, i, reg):
    # full native registers
    if reg in ctx.registers:
        return ctx.registers[reg]

    raise TranslationError('Unsupported register!')


def _get_register_size(ctx, i, reg_id):
    # full native registers
    if reg_id in ctx.registers:
        return ctx.registers[reg_id].size

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

    if opnd.type == capstone.arm.ARM_OP_REG:
        return _get_register(ctx, i, opnd.reg)

    elif opnd.type == capstone.arm.ARM_OP_IMM:
        return _get_immediate(ctx, i, opnd, size)

    elif opnd.type == capstone.arm.ARM_OP_MEM:
        return _get_memory(ctx, i, opnd)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def get_size(ctx, i, index, size=0):

    opnd = i.operands[index]

    if opnd.type == capstone.arm.ARM_OP_REG:
        return _get_register_size(ctx, i, opnd.reg)

    elif opnd.type == capstone.arm.ARM_OP_IMM:
        return _get_immediate(ctx, i, opnd, size).size

    elif opnd.type == capstone.arm.ARM_OP_MEM:
        return _get_memory_size(ctx, i, opnd)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def is_register(ctx, i, index):
    return i.operands[index].type == capstone.arm.ARM_OP_REG


def is_immediate(ctx, i, index):
    return i.operands[index].type == capstone.arm.ARM_OP_IMM


def is_memory(ctx, i, index):
    return i.operands[index].type == capstone.arm.ARM_OP_MEM


def _set_register(ctx, i, reg_id, value, clear=False, sign_extend=False):
    # full native registers
    if reg_id in ctx.registers:
        reg = ctx.registers[reg_id]
    else:
        raise TranslationError('Unsupported register!')

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

    if opnd.type == capstone.arm.ARM_OP_REG:
        return _set_register(ctx, i, opnd.reg, value, clear, sign_extend)

    elif opnd.type == capstone.arm.ARM_OP_MEM:
        return _set_memory(ctx, i, opnd, value)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def set_register(ctx, i, name, value, clear=False, sign_extend=False):
    reg_id = _reg_id_from_name(name)

    return _set_register(ctx, i, reg_id, value, clear, sign_extend)


def _undef_register(ctx, i, reg_id, value, clear=False, sign_extend=False):

    # full native registers
    if reg_id in ctx.registers:
        reg = ctx.registers[reg_id]

    else:
        raise TranslationError('Unsupported register!')

    ctx.emit(  undef_  (reg))


def undefine(ctx, i, index):

    opnd = i.operands[index]

    if opnd.type == capstone.arm.ARM_OP_REG:
        _undef_register(ctx, i, opnd.reg)

    else:
        raise TranslationError('Can only call operand.undefine on a register operand')


def writeback(ctx, i, index):

    opnd = i.operands[index]

    if opnd.type == capstone.arm.ARM_OP_MEM:
        address = _memory_address(ctx, i, opnd)

        _set_register(ctx, i, opnd.mem.base, address)

    else:
        raise TranslationError('Can only call operand.writeback on a memory operand')