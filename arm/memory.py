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

"""reil.arm.memory - ARMv7 and Thumbv2 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv7 and Thumbv2 machine code.

This file is responsible for translation of memory related instructions
such as ldm, stm, push, pop
"""

import reil.error
from reil import *
from reil.shorthand import *
from reil.utilities import *

import reil.arm.operand as operand
from reil.arm.utilities import *


def _arm_mov(ctx, i):
    prev_value = operand.get(ctx, i, 1)
    value = ctx.tmp(ctx.word_size)

    ctx.emit(  str_  (prev_value, value))

    if i.update_flags:
        set_N(ctx, value)
        set_Z(ctx, value)

    operand.set(ctx, i, 0, value)


def arm_mov(ctx, i):
    _arm_mov(ctx, i)


def arm_movt(ctx, i):
    # first extract the low 16 bits of the destination
    prev_value = operand.get(ctx, i, 0)
    value = ctx.tmp(ctx.word_size)

    ctx.emit(  and_  (prev_value, imm(mask(16), 32), value))

    # then compute the high 16 bits
    prev_result = operand.get(ctx, i, 1)
    result = ctx.tmp(ctx.word_size)

    ctx.emit(  str_  (prev_result, result))
    ctx.emit(  lshl_ (result, imm(16, 32), result))

    ctx.emit(  or_   (value, result, result))

    if i.update_flags:
        set_N(ctx, result)
        set_Z(ctx, result)

    operand.set(ctx, i, 0, result)


def arm_movw(ctx, i):
    _arm_mov(ctx, i)


def arm_push(ctx, i):
    for op in i.operands:
        value = operand.get(ctx, i, 0)

        ctx.emit(  sub_  (ctx.stack_ptr,
                          imm(ctx.word_size // 8, ctx.word_size),
                          ctx.stack_ptr))

        if value.size != ctx.word_size:
            prev_value = value
            value = ctx.tmp(ctx.word_size)
            ctx.emit(  sex_  (prev_value, value))

        ctx.emit(  stm_  (value, ctx.stack_ptr))


def arm_stm(ctx, i):
    value = operand.get(ctx, i, 0)
    address = operand.get(ctx, i, 1)

    ctx.emit(  stm_  (value, address))

    if i.writeback:
        operand.writeback(ctx, i, 1)


def arm_str(ctx, i):
    value = operand.get(ctx, i, 1)
    operand.set(ctx, i, 0, value)

