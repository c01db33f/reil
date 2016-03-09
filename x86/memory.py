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

"""reil.x86.memory - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of memory related instructions
such as lea, mov, push, pop
"""

import capstone

import reil.error
from reil import *
from reil.shorthand import *
from reil.utilities import *

import reil.x86.arithmetic as arithmetic
import reil.x86.conditional as conditional
import reil.x86.operand as operand
from reil.x86.utilities import *


def conditional_mov(ctx, i, condition):
    c = conditional.condition(ctx, condition)

    value = None

    if len(i.operands) == 1:
        # source is the accumulator
        value = ctx.accumulator
    else:
        value = operand.get(ctx, i, 1)

    ctx.emit(  jcc_  (c, 'do_mov'))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('do_mov')
    operand.set(ctx, i, 0, value, clear=True)

    ctx.emit('done')
    ctx.emit(  nop_())


def rep_prologue(ctx, i):
    tmp = ctx.tmp(64)

    # counter == 0 is only condition in which we terminate without executing
    ctx.emit(  bisz_ (ctx.counter, tmp))
    ctx.emit(  jcc_  (tmp, imm(i.address + i.size, ctx.word_size)))


def rep_epilogue(ctx, i):
    cond = ctx.tmp(8)

    ctx.emit(  sub_  (ctx.counter, imm(1, ctx.word_size), ctx.counter))
    ctx.emit(  bisnz_(ctx.counter, cond))

    if i.mnemonic.startswith('repne'):
        # repeat if counter > 0 and zf not set
        tmp = ctx.tmp(8)
        ctx.emit(  bisz_ (r('zf', 8), tmp))
        ctx.emit(  and_  (tmp, cond, cond))

    elif i.mnemonic.startswith('repe') or 'cmps' in i.mnemonic:
        # repeat if counter > 0 and zf set
        ctx.emit(  and_  (r('zf', 8), cond, cond))

    # we're not done, jump back to start of instruction
    ctx.emit(  jcc_  (cond, off(0)))

    # TODO: decide which of these is preferable; or add a flag to translation
    # to determine whether we unroll rep x; instructions.
    #ctx.emit(  jcc_  (cond, imm(i.address, ctx.word_size)))


def x86_cmova(ctx, i):
    """mov if above"""
    conditional_mov(ctx, i, conditional.A)


def x86_cmovae(ctx, i):
    """mov if above or equal"""
    conditional_mov(ctx, i, conditional.AE)


def x86_cmovb(ctx, i):
    """mov if bigger"""
    conditional_mov(ctx, i, conditional.B)


def x86_cmovbe(ctx, i):
    """mov if bigger or equal"""
    conditional_mov(ctx, i, conditional.BE)


def x86_cmove(ctx, i):
    """mov if equal"""
    conditional_mov(ctx, i, conditional.E)


def x86_cmovg(ctx, i):
    """mov if greater"""
    conditional_mov(ctx, i, conditional.G)


def x86_cmovge(ctx, i):
    """mov if greater or equal"""
    conditional_mov(ctx, i, conditional.GE)


def x86_cmovl(ctx, i):
    """mov if less"""
    conditional_mov(ctx, i, conditional.L)


def x86_cmovle(ctx, i):
    """mov if less or equal"""
    conditional_mov(ctx, i, conditional.LE)


def x86_cmovne(ctx, i):
    """mov if not equal"""
    conditional_mov(ctx, i, conditional.NE)


def x86_cmovno(ctx, i):
    """mov if not overflow"""
    conditional_mov(ctx, i, conditional.NO)


def x86_cmovnp(ctx, i):
    """mov if not parity"""
    conditional_mov(ctx, i, conditional.NP)


def x86_cmovns(ctx, i):
    """mov if not sign"""
    conditional_mov(ctx, i, conditional.NS)


def x86_cmovo(ctx, i):
    """mov if overflow"""
    conditional_mov(ctx, i, conditional.O)


def x86_cmovp(ctx, i):
    """mov if parity"""
    conditional_mov(ctx, i, conditional.P)


def x86_cmovs(ctx, i):
    """mov if sign"""
    conditional_mov(ctx, i, conditional.S)


def x86_cmps(ctx, i, size):

    src = ctx.source
    dst = ctx.destination

    result = ctx.tmp(size * 2)

    value1 = ctx.tmp(size)
    address1 = ctx.tmp(src.size)

    value2 = ctx.tmp(size)
    address2 = ctx.tmp(src.size)

    if i.mnemonic.startswith('rep'):
        rep_prologue(ctx, i)

    # read the values
    ctx.emit(  str_  (src, address1))
    ctx.emit(  ldm_  (address1, value1))

    ctx.emit(  str_  (dst, address2))
    ctx.emit(  ldm_  (address2, value2))

    # do the comparison and set flags
    ctx.emit(  sub_  (value1, value2, result))
    arithmetic._sub_set_flags(ctx, value1, value2, result)

    # do the increment/decrement
    ctx.emit(  jcc_  (r('df', 8), 'decrement'))
    ctx.emit('increment')
    ctx.emit(  add_  (address1, imm(size // 8, ctx.word_size), address1))
    ctx.emit(  add_  (address2, imm(size // 8, ctx.word_size), address2))
    ctx.emit(  jcc_  (imm(1, 8), 'set'))
    ctx.emit('decrement')
    ctx.emit(  sub_  (address1, imm(size // 8, ctx.word_size), address1))
    ctx.emit(  sub_  (address2, imm(size // 8, ctx.word_size), address2))
    ctx.emit('set')
    ctx.emit(  str_  (address1, ctx.source))
    ctx.emit(  str_  (address2, ctx.destination))

    if i.mnemonic.startswith('rep'):
        rep_epilogue(ctx, i)


def x86_cmpsb(ctx, i):
    x86_cmps(ctx, i, 8)


def x86_cmpsw(ctx, i):
    x86_cmps(ctx, i, 16)


def x86_cmpsd(ctx, i):
    x86_cmps(ctx, i, 32)


def x86_cmpsq(ctx, i):
    x86_cmps(ctx, i, 64)


def x86_lea(ctx, i):
    address = operand.get_address(ctx, i, 1)
    operand.set(ctx, i, 0, address, clear=True)


def x86_leave(ctx, i):
    ctx.emit(  str_  (ctx.frame_ptr, ctx.stack_ptr))
    ctx.emit(  ldm_  (ctx.stack_ptr, ctx.frame_ptr))

    # TODO: This does not handle overflow. But I don't know what happens
    # if the stack pointer overflows...

    ctx.emit(  add_  (ctx.stack_ptr,
                      imm(ctx.word_size // 8, ctx.word_size),
                      ctx.stack_ptr))


def x86_lods(ctx, i, size):
    src = ctx.source

    value = ctx.tmp(size)

    if i.mnemonic.startswith('rep'):
        rep_prologue(ctx, i)

    ctx.emit(  ldm_  (src, value))

    if size == 8:
        operand.set_register(ctx, i, 'al', value)
    elif size == 16:
        operand.set_register(ctx, i, 'ax', value)
    elif size == 32:
        operand.set_register(ctx, i, 'eax', value)
    else:
        operand.set_register(ctx, i, 'rax', value)

    ctx.emit(  jcc_  (r('df', 8), 'decrement'))
    ctx.emit('increment')
    ctx.emit(  add_  (src, imm(value.size // 8, ctx.word_size), src))
    ctx.emit(  jcc_  (imm(1, 8), 'set'))
    ctx.emit('decrement')
    ctx.emit(  sub_  (src, imm(value.size // 8, ctx.word_size), src))
    ctx.emit('set')
    ctx.emit(  str_  (src, ctx.source))

    if i.mnemonic.startswith('rep'):
        rep_epilogue(ctx, i)


def x86_lodsb(ctx, i):
    x86_lods(ctx, i, 8)


def x86_lodsd(ctx, i):
    x86_lods(ctx, i, 32)


def x86_lodsq(ctx, i):
    x86_lods(ctx, i, 64)


def x86_lodsw(ctx, i):
    x86_lods(ctx, i, 16)


def x86_mov(ctx, i):
    size = operand.get_size(ctx, i, 0)
    value = None

    clear = True
    if len(i.operands) == 1:
        # source is the accumulator
        value = ctx.accumulator

        if i.operands[0].type == capstone.x86.X86_OP_REG:
            clear = False
    else:
        value = operand.get(ctx, i, 1, size=size)

        if (i.operands[0].type == capstone.x86.X86_OP_REG and
            i.operands[1].type == capstone.x86.X86_OP_REG):
            clear = False

    # Oh x86 how I hate you
    if i.operands[1].type == capstone.x86.X86_OP_MEM and operand.get_size(ctx, i, 1) != 32:
        clear = False

    operand.set(ctx, i, 0, value, clear=clear)


def x86_movabs(ctx, i):
    x86_mov(ctx, i)


def x86_movs(ctx, i, size):
    # This is to handle the mnemonic overload (SSE movsd) for 'move scalar
    # double-precision floating-point value' since capstone doesn't
    # distinguish. That instruction is just a mov into/from the SSE
    # registers.
    if not operand.is_memory(ctx, i, 0) or not operand.is_memory(ctx, i, 1):
      # so basically, if one of the operands is not a memory address, then we
      # know that this is the SSE version, which x86_mov can handle.
      return x86_mov(ctx, i)

    value = ctx.tmp(size)

    if i.mnemonic.startswith('rep'):
        rep_prologue(ctx, i)

    ctx.emit(  ldm_  (ctx.source, value))
    ctx.emit(  stm_  (value, ctx.destination))
    ctx.emit(  jcc_  (r('df', 8), 'decrement'))
    ctx.emit('increment')
    ctx.emit(  add_  (ctx.destination, imm(value.size // 8, ctx.word_size), ctx.destination))
    ctx.emit(  add_  (ctx.source, imm(value.size // 8, ctx.word_size), ctx.source))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))
    ctx.emit('decrement')
    ctx.emit(  sub_  (ctx.destination, imm(value.size // 8, ctx.word_size), ctx.destination))
    ctx.emit(  sub_  (ctx.source, imm(value.size // 8, ctx.word_size), ctx.source))
    ctx.emit('done')
    ctx.emit(  nop_  ())

    if i.mnemonic.startswith('rep'):
        rep_epilogue(ctx, i)


def x86_movsb(ctx, i):
    x86_movs(ctx, i, 8)


def x86_movsd(ctx, i):
    x86_movs(ctx, i, 32)


def x86_movsq(ctx, i):
    x86_movs(ctx, i, 64)


def x86_movsw(ctx, i):
    x86_movs(ctx, i, 16)


def x86_movsx(ctx, i):
    value = None

    if len(i.operands) == 1:
        # source is the accumulator
        value = ctx.accumulator
    else:
        value = operand.get(ctx, i, 1)

    operand.set(ctx, i, 0, value, clear=True, sign_extend=True)


def x86_movzx(ctx, i):
    value = None

    if len(i.operands) == 1:
        # source is the accumulator
        value = ctx.accumulator
    else:
        value = operand.get(ctx, i, 1)

    operand.set(ctx, i, 0, value, clear=True, sign_extend=False)


def x86_pop(ctx, i):
    a = operand.get(ctx, i, 0)
    value = ctx.tmp(a.size)

    ctx.emit(  ldm_  (ctx.stack_ptr, value))
    ctx.emit(  add_  (ctx.stack_ptr,
                      imm(value.size // 8, ctx.word_size),
                      ctx.stack_ptr))

    operand.set(ctx, i, 0, value)


def x86_push(ctx, i):
    value = operand.get(ctx, i, 0)

    ctx.emit(  sub_  (ctx.stack_ptr,
                      imm(ctx.word_size // 8, ctx.word_size),
                      ctx.stack_ptr))

    if value.size != ctx.word_size:
        prev_value = value
        value = ctx.tmp(ctx.word_size)
        ctx.emit(  sex_  (prev_value, value))

    ctx.emit(  stm_  (value, ctx.stack_ptr))


def x86_scas(ctx, i, size):

    a = ctx.destination
    b = r(ctx.accumulator.name, size)
    value = ctx.tmp(size)
    result = ctx.tmp(size * 2)
    address = ctx.tmp(a.size)

    if i.mnemonic.startswith('rep'):
        rep_prologue(ctx, i)

    ctx.emit(  str_  (a, address))

    # read the value
    ctx.emit(  ldm_  (address, value))

    # do the comparison and set flags
    ctx.emit(  sub_  (value, b, result))
    arithmetic._sub_set_flags(ctx, a, b, result)

    # do the increment/decrement
    ctx.emit(  jcc_  (r('df', 8), 'decrement'))
    ctx.emit('increment')
    ctx.emit(  add_  (address, imm(value.size // 8, ctx.word_size), address))
    ctx.emit(  jcc_  (imm(1, 8), 'set'))
    ctx.emit('decrement')
    ctx.emit(  sub_  (address, imm(value.size // 8, ctx.word_size), address))
    ctx.emit('set')
    ctx.emit(  str_  (address, ctx.destination))

    if i.mnemonic.startswith('rep'):
        rep_epilogue(ctx, i)


def x86_scasb(ctx, i):
    x86_scas(ctx, i, 8)


def x86_scasd(ctx, i):
    x86_scas(ctx, i, 32)


def x86_scasq(ctx, i):
    x86_scas(ctx, i, 64)


def x86_scasw(ctx, i):
    x86_scas(ctx, i, 16)


def x86_stos(ctx, i, size):
    a = ctx.destination
    value = ctx.accumulator

    if size != value.size:
        prev_value = value
        value = ctx.tmp(size)
        ctx.emit(  str_  (prev_value, value))

    address = ctx.tmp(a.size)

    if i.mnemonic.startswith('rep'):
        rep_prologue(ctx, i)

    ctx.emit(  str_  (a, address))
    ctx.emit(  stm_  (value, address))
    ctx.emit(  jcc_  (r('df', 8), 'decrement'))
    ctx.emit('increment')
    ctx.emit(  add_  (address, imm(value.size // 8, ctx.word_size), address))
    ctx.emit(  jcc_  (imm(1, 8), 'set'))
    ctx.emit('decrement')
    ctx.emit(  sub_  (address, imm(value.size // 8, ctx.word_size), address))
    ctx.emit('set')
    ctx.emit(  str_  (address, ctx.destination))

    if i.mnemonic.startswith('rep'):
        rep_epilogue(ctx, i)


def x86_stosb(ctx, i):
    x86_stos(ctx, i, 8)


def x86_stosd(ctx, i):
    x86_stos(ctx, i, 32)


def x86_stosq(ctx, i):
    x86_stos(ctx, i, 64)


def x86_stosw(ctx, i):
    x86_stos(ctx, i, 16)

