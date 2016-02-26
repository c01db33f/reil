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

"""reil.arm64.arithmetic - ARMv8 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv8 machine code.

This file is responsible for translation of basic arithmetic instructions
such as add, mul, div
"""

import reil.error
from reil import *
from reil.shorthand import *
from reil.utilities import *

import reil.arm64.operand as operand

def _arithmetic_set_flags(ctx, sign_a, sign_b, result):
    size = sign_a.size

    sign_result = ctx.tmp(size)

    tmp0 = ctx.tmp(size)
    tmp1 = ctx.tmp(size)
    tmp2 = ctx.tmp(size)
    tmp3 = ctx.tmp(size)
    tmp4 = ctx.tmp(result.size)

    ctx.emit(  and_  (result, imm(sign_bit(size), size), sign_result))

    # compute overflow flag

    # tmp0 = (sign a != sign result)
    ctx.emit(  xor_  (sign_a, sign_result, tmp0))
    # tmp1 = (sign b != sign result)
    ctx.emit(  xor_  (sign_b, sign_result, tmp1))
    # tmp2 = (sign a != sign result) && (sign b != sign result)
    ctx.emit(  and_  (tmp0, tmp1, tmp2))
    ctx.emit(  bisnz_(tmp2, r('v', 8)))

    # compute sign flag (easy...)
    ctx.emit(  bisnz_(sign_result, r('n', 8)))

    # compute zero flag (easy...)
    ctx.emit(  and_  (result, imm(mask(size), size), tmp3))
    ctx.emit(  bisz_ (tmp3, r('z', 8)))

    # compute carry flag
    ctx.emit(  and_  (result, imm(carry_bit(size), result.size), tmp4))
    ctx.emit(  bisnz_(tmp4, r('c', 8)))


def _sub_set_flags(ctx, a, b, result):
    size = a.size

    tmp0 = ctx.tmp(size)

    sign_a = ctx.tmp(size)
    sign_b = ctx.tmp(size)

    ctx.emit(  and_  (a, imm(sign_bit(size), size), sign_a))
    ctx.emit(  xor_  (b, imm(sign_bit(size), size), tmp0))
    ctx.emit(  and_  (tmp0, imm(sign_bit(size), size), sign_b))

    _arithmetic_set_flags(ctx, sign_a, sign_b, result)


def arm64_sub(ctx, i):
    if len(i.operands) == 3:
        dst_idx = 0
        a_idx = 1
        b_idx = 2
    else:
        dst_idx = 0
        a_idx = 0
        b_idx = 1

    a = operand.get(ctx, i, a_idx)
    b = operand.get(ctx, i, b_idx, a.size)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  sub_  (a, b, result))

    if i.update_flags:
        _sub_set_flags(ctx, a, b, result)

    operand.set(ctx, i, dst_idx, result)

