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

"""reil.x86.control_flow - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of control flow instructions
such as call, jmp and ret.
"""

import reil.x86.conditional as conditional
import reil.x86.operand as operand

from reil.shorthand import *
from reil.utilities import *

# Helpers

def conditional_jump(ctx, i, condition):
    c = conditional.condition(ctx, condition)
    dst = operand.get(ctx, i, 0)

    ctx.emit(  jcc_   (c, dst))


def _push(ctx, i, value):
    if value.size != ctx.word_size:
        prev_value = value
        value = ctx.tmp(ctx.word_size)
        ctx.emit(  str_  (prev_value, value))

    ctx.emit(  sub_  (ctx.stack_ptr,
                      imm(ctx.word_size // 8, ctx.word_size),
                      ctx.stack_ptr))

    ctx.emit(  stm_  (value, ctx.stack_ptr))


# Instruction Translators

def x86_call(ctx, i):
    """call procedure"""
    dst = operand.get(ctx, i, 0)

    _push(ctx, i, imm(i.address + i.size, ctx.word_size))

    ctx.emit(  jcc_  (imm(1, 8), dst))


def x86_enter(ctx, i):
    size = operand.get(ctx, i, 0)
    nest = operand.get(ctx, i, 1)

    frame_tmp = ctx.stack_ptr

    _push(ctx, i, ctx.frame_ptr)

    if nest.value > 0:
        frame_tmp = ctx.tmp(ctx.word_size)
        ctx.emit(  str_  (ctx.stack_ptr, frame_tmp))

        for i in range(1, nest.value):
            ctx.emit(  sub_  (ctx.frame_ptr, imm(4, ctx.word_size), ctx.frame_ptr))
            _push(ctx, i, ctx.frame_ptr)

        _push(frame_tmp)

    ctx.emit(  str_  (frame_tmp, ctx.frame_ptr))
    ctx.emit(  sub_  (ctx.frame_ptr, size, ctx.stack_ptr))


def x86_ja(ctx, i):
    """jump if above"""
    conditional_jump(ctx, i, conditional.A)


def x86_jae(ctx, i):
    """jump if above or equal"""
    conditional_jump(ctx, i, conditional.AE)


def x86_jb(ctx, i):
    """jump if bigger"""
    conditional_jump(ctx, i, conditional.B)


def x86_jbe(ctx, i):
    """jump if bigger or equal"""
    conditional_jump(ctx, i, conditional.BE)


def x86_jcxz(ctx, i):
    """jump if cx is zero"""
    conditional_jump(ctx, i, conditional.CXZ)


def x86_jecxz(ctx, i):
    """jump if ecx is zero"""
    conditional_jump(ctx, i, conditional.ECXZ)


def x86_jrcxz(ctx, i):
    """jump if rcx is zero"""
    conditional_jump(ctx, i, conditional.RCXZ)


def x86_je(ctx, i):
    """jump if equal"""
    conditional_jump(ctx, i, conditional.E)


def x86_jg(ctx, i):
    """jump if greater"""
    conditional_jump(ctx, i, conditional.G)


def x86_jge(ctx, i):
    """jump if greater or equal"""
    conditional_jump(ctx, i, conditional.GE)


def x86_jl(ctx, i):
    """jump if less"""
    conditional_jump(ctx, i, conditional.L)


def x86_jle(ctx, i):
    """jump if less or equal"""
    conditional_jump(ctx, i, conditional.LE)


def x86_jmp(ctx, i):
    """jump"""
    conditional_jump(ctx, i, conditional.UN)


def x86_jne(ctx, i):
    """jump if not equal"""
    conditional_jump(ctx, i, conditional.NE)


def x86_jno(ctx, i):
    """jump if not overflow"""
    conditional_jump(ctx, i, conditional.NO)


def x86_jnp(ctx, i):
    """jump if not parity"""
    conditional_jump(ctx, i, conditional.NP)


def x86_jns(ctx, i):
    """jump if not sign"""
    conditional_jump(ctx, i, conditional.NS)


def x86_jo(ctx, i):
    """jump if overflow"""
    conditional_jump(ctx, i, conditional.O)


def x86_jp(ctx, i):
    """jump if parity"""
    conditional_jump(ctx, i, conditional.P)


def x86_js(ctx, i):
    """jump if sign"""
    conditional_jump(ctx, i, conditional.S)


def x86_loop(ctx, i):
    c = ctx.tmp(8)
    dst = operand.get(ctx, i, 0)

    ctx.emit(  sub_  (ctx.counter, imm(1, ctx.counter.size), ctx.counter))
    ctx.emit(  equ_  (ctx.counter, imm(0, ctx.counter.size), c))
    ctx.emit(  jcc_  (c, dst))


def x86_loope(ctx, i):
    c = conditional.condition(ctx, conditional.E)
    dst = operand.get(ctx, i, 0)

    tmp0 = ctx.tmp(8)

    ctx.emit(  sub_  (ctx.counter, imm(1, ctx.counter.size), ctx.counter))
    ctx.emit(  equ_  (ctx.counter, imm(0, ctx.counter.size), tmp0))
    ctx.emit(  or_   (c, tmp0, c))
    ctx.emit(  jcc_  (c, dst))


def x86_loopne(ctx, i):
    c = conditional.condition(ctx, conditional.NE)
    dst = operand.get(ctx, i, 0)

    tmp0 = ctx.tmp(8)

    ctx.emit(  sub_  (ctx.counter, imm(1, ctx.counter.size), ctx.counter))
    ctx.emit(  equ_  (ctx.counter, imm(0, ctx.counter.size), tmp0))
    ctx.emit(  or_   (c, tmp0, c))
    ctx.emit(  jcc_  (c, dst))


def x86_ret(ctx, i):
    """return from procedure"""

    return_address = ctx.tmp(ctx.word_size)

    ctx.emit(  ldm_  (ctx.stack_ptr, return_address))

    if len(i.operands) > 0:
        a = operand.get(ctx, i, 0)
        ctx.emit(  add_  (ctx.stack_ptr,
                          imm(a.value + (ctx.word_size // 8), ctx.word_size),
                          ctx.stack_ptr))

    else:
        ctx.emit(  add_  (ctx.stack_ptr,
                          imm(ctx.word_size // 8, ctx.word_size),
                          ctx.stack_ptr))

    ctx.emit(  jcc_  (imm(1, 8), return_address))