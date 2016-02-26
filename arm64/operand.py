# -*- coding: utf-8 -*-

#    Copyright 2016 Mark Brand - c01db33f (at) gmail.com
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

"""reil.arm64.operands - ARMv8 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv8 machine code.

This file contains helpers for reading and writing instruction
operands.
"""

import capstone

from reil.error import *
from reil.shorthand import *
from reil.utilities import *


def _reg_id_from_name(name):
    register_lookup = {
        'x0':  capstone.arm64.ARM64_REG_X0,
        'x1':  capstone.arm64.ARM64_REG_X1,
        'x2':  capstone.arm64.ARM64_REG_X2,
        'x3':  capstone.arm64.ARM64_REG_X3,
        'x4':  capstone.arm64.ARM64_REG_X4,
        'x5':  capstone.arm64.ARM64_REG_X5,
        'x6':  capstone.arm64.ARM64_REG_X6,
        'x7':  capstone.arm64.ARM64_REG_X7,
        'x8':  capstone.arm64.ARM64_REG_X8,
        'x9':  capstone.arm64.ARM64_REG_X9,
        'x10': capstone.arm64.ARM64_REG_X10,
        'x11': capstone.arm64.ARM64_REG_X11,
        'x12': capstone.arm64.ARM64_REG_X12,
        'x13': capstone.arm64.ARM64_REG_X13,
        'x14': capstone.arm64.ARM64_REG_X14,
        'x15': capstone.arm64.ARM64_REG_X15,
        'x16': capstone.arm64.ARM64_REG_X16,
        'x17': capstone.arm64.ARM64_REG_X17,
        'x18': capstone.arm64.ARM64_REG_X18,
        'x19': capstone.arm64.ARM64_REG_X19,
        'x20': capstone.arm64.ARM64_REG_X20,
        'x21': capstone.arm64.ARM64_REG_X21,
        'x22': capstone.arm64.ARM64_REG_X22,
        'x23': capstone.arm64.ARM64_REG_X23,
        'x24': capstone.arm64.ARM64_REG_X24,
        'x25': capstone.arm64.ARM64_REG_X25,
        'x26': capstone.arm64.ARM64_REG_X26,
        'x27': capstone.arm64.ARM64_REG_X27,
        'x28': capstone.arm64.ARM64_REG_X28,
        'x29': capstone.arm64.ARM64_REG_X29,
        'x30': capstone.arm64.ARM64_REG_X30,
        'x31': capstone.arm64.ARM64_REG_X31,
        'xzr': capstone.arm64.ARM64_REG_XZR,
        'sp':  capstone.arm64.ARM64_REG_SP,
        'lr':  capstone.arm64.ARM64_REG_LR,
    }

    if name not in register_lookup:
        raise TranslationError('Invalid Register {}'.format(name))

    return register_lookup[name]


def _memory_address(ctx, i, opnd, writeback=False):
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

    if writeback:
        _set_register(ctx, i, opnd.mem.base, address) 

    return address


def _get_memory_size(ctx, i, opnd):
    # TODO: how to get this...
    return 32

def _get_register(ctx, i, reg_id):
    # 32-bit registers
    wregs = {
        capstone.arm64.ARM64_REG_W0:  r('x0', 64),
        capstone.arm64.ARM64_REG_W1:  r('x1', 64),
        capstone.arm64.ARM64_REG_W2:  r('x2', 64),
        capstone.arm64.ARM64_REG_W3:  r('x3', 64),
        capstone.arm64.ARM64_REG_W4:  r('x4', 64),
        capstone.arm64.ARM64_REG_W5:  r('x5', 64),
        capstone.arm64.ARM64_REG_W6:  r('x6', 64),
        capstone.arm64.ARM64_REG_W7:  r('x7', 64),
        capstone.arm64.ARM64_REG_W8:  r('x8', 64),
        capstone.arm64.ARM64_REG_W9:  r('x9', 64),
        capstone.arm64.ARM64_REG_W10: r('x10', 64),
        capstone.arm64.ARM64_REG_W11: r('x11', 64),
        capstone.arm64.ARM64_REG_W12: r('x12', 64),
        capstone.arm64.ARM64_REG_W13: r('x13', 64),
        capstone.arm64.ARM64_REG_W14: r('x14', 64),
        capstone.arm64.ARM64_REG_W15: r('x15', 64),
        capstone.arm64.ARM64_REG_W16: r('x16', 64),
        capstone.arm64.ARM64_REG_W17: r('x17', 64),
        capstone.arm64.ARM64_REG_W18: r('x18', 64),
        capstone.arm64.ARM64_REG_W19: r('x19', 64),
        capstone.arm64.ARM64_REG_W20: r('x20', 64),
        capstone.arm64.ARM64_REG_W21: r('x21', 64),
        capstone.arm64.ARM64_REG_W22: r('x22', 64),
        capstone.arm64.ARM64_REG_W23: r('x23', 64),
        capstone.arm64.ARM64_REG_W24: r('x24', 64),
        capstone.arm64.ARM64_REG_W25: r('x25', 64),
        capstone.arm64.ARM64_REG_W26: r('x26', 64),
        capstone.arm64.ARM64_REG_W27: r('x27', 64),
        capstone.arm64.ARM64_REG_W28: r('x28', 64),
        capstone.arm64.ARM64_REG_W29: r('x29', 64),
        capstone.arm64.ARM64_REG_W30: r('x30', 64),
        capstone.arm64.ARM64_REG_WSP: r('sp', 64),
    }
    
    if reg_id in wregs:
        wreg = wregs[reg_id]
        value = ctx.tmp(32)
        ctx.emit(  str_  (wreg, value))
        return value

    elif reg_id in ctx.registers:
        return ctx.registers[reg_id]

    else:
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

    if opnd.type == capstone.arm64.ARM64_OP_REG:
        return _get_register_size(ctx, i, opnd.reg)

    elif opnd.type == capstone.arm64.ARM64_OP_IMM:
        return _get_immediate(ctx, i, opnd, size).size

    elif opnd.type == capstone.arm64.ARM64_OP_MEM:
        return _get_memory_size(ctx, i, opnd)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def is_register(ctx, i, index):
    return i.operands[index].type == capstone.arm.ARM64_OP_REG


def is_immediate(ctx, i, index):
    return i.operands[index].type == capstone.arm.ARM64_OP_IMM


def is_memory(ctx, i, index):
    return i.operands[index].type == capstone.arm.ARM64_OP_MEM


def _set_register(ctx, i, reg_id, value):
    # zero register is never set
    if reg_id == capstone.arm64.ARM64_REG_XZR or reg_id == capstone.arm64.ARM64_REG_WZR:
      return

    # 32-bit registers
    wregs = {
        capstone.arm64.ARM64_REG_W0:  r('x0', 64),
        capstone.arm64.ARM64_REG_W1:  r('x1', 64),
        capstone.arm64.ARM64_REG_W2:  r('x2', 64),
        capstone.arm64.ARM64_REG_W3:  r('x3', 64),
        capstone.arm64.ARM64_REG_W4:  r('x4', 64),
        capstone.arm64.ARM64_REG_W5:  r('x5', 64),
        capstone.arm64.ARM64_REG_W6:  r('x6', 64),
        capstone.arm64.ARM64_REG_W7:  r('x7', 64),
        capstone.arm64.ARM64_REG_W8:  r('x8', 64),
        capstone.arm64.ARM64_REG_W9:  r('x9', 64),
        capstone.arm64.ARM64_REG_W10: r('x10', 64),
        capstone.arm64.ARM64_REG_W11: r('x11', 64),
        capstone.arm64.ARM64_REG_W12: r('x12', 64),
        capstone.arm64.ARM64_REG_W13: r('x13', 64),
        capstone.arm64.ARM64_REG_W14: r('x14', 64),
        capstone.arm64.ARM64_REG_W15: r('x15', 64),
        capstone.arm64.ARM64_REG_W16: r('x16', 64),
        capstone.arm64.ARM64_REG_W17: r('x17', 64),
        capstone.arm64.ARM64_REG_W18: r('x18', 64),
        capstone.arm64.ARM64_REG_W19: r('x19', 64),
        capstone.arm64.ARM64_REG_W20: r('x20', 64),
        capstone.arm64.ARM64_REG_W21: r('x21', 64),
        capstone.arm64.ARM64_REG_W22: r('x22', 64),
        capstone.arm64.ARM64_REG_W23: r('x23', 64),
        capstone.arm64.ARM64_REG_W24: r('x24', 64),
        capstone.arm64.ARM64_REG_W25: r('x25', 64),
        capstone.arm64.ARM64_REG_W26: r('x26', 64),
        capstone.arm64.ARM64_REG_W27: r('x27', 64),
        capstone.arm64.ARM64_REG_W28: r('x28', 64),
        capstone.arm64.ARM64_REG_W29: r('x29', 64),
        capstone.arm64.ARM64_REG_W30: r('x30', 64),
        capstone.arm64.ARM64_REG_WSP: r('sp', 64),
    }
    
    if reg_id in wregs:
        # 32-bit extensions always zero-extend.
        reg = wregs[reg_id]
    elif reg_id in ctx.registers:
        reg = ctx.registers[reg_id]
    else:
        raise TranslationError('Unsupported register!')

    ctx.emit(  str_  (value, reg))


def _set_memory(ctx, i, opnd, value, writeback=False):

    address = _memory_address(ctx, i, opnd, writeback)
    write_size = _get_memory_size(ctx, i, opnd)

    if value.size > write_size:

        prev_value = value
        value = ctx.tmp(write_size)

        ctx.emit(  str_  (prev_value, value))

    ctx.emit(  stm_  (value, address))


def set(ctx, i, index, value, writeback=False):

    opnd = i.operands[index]

    if opnd.type == capstone.arm.ARM_OP_REG:
        return _set_register(ctx, i, opnd.reg, value)

    elif opnd.type == capstone.arm.ARM_OP_MEM:
        return _set_memory(ctx, i, opnd, value, writeback)

    else:
        raise TranslationError(
            'Unsupported operand type!')


def set_register(ctx, i, name, value):
    reg_id = _reg_id_from_name(name)

    return _set_register(ctx, i, reg_id, value)


def _undef_register(ctx, i, reg_id, value):

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
        # TODO: this is completely wrong.

        _set_register(ctx, i, opnd.mem.base, address)

    else:
        raise TranslationError('Can only call operand.writeback on a memory operand')
