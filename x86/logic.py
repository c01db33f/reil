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

"""reil.x86.logic - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of basic logical instructions
such as and, or, xor
"""

import reil.error
from reil.shorthand import *
from reil.utilities import *

import reil.x86.conditional as conditional
import reil.x86.operand as operand
from reil.x86.utilities import *


# Helpers

def _logic_set_flags(ctx, result):

    size = result.size

    sign_result = ctx.tmp(size)

    ctx.emit(  and_  (result, imm(sign_bit(size), size), sign_result))

    # clear overflow flag
    ctx.emit(  str_  (imm(0, 8), r('of', 8)))

    # compute sign flag (easy...)
    ctx.emit(  bisnz_(sign_result, r('sf', 8)))

    # compute zero flag (easy...)
    ctx.emit(  bisz_ (result, r('zf', 8)))

    # TODO: compute adjust flag? expensive...

    # clear carry flag
    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))

    set_pf(ctx, result)


# Instruction Translators

def x86_and(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1, a.size)

    size = min(a.size, b.size)
    result = ctx.tmp(size)

    ctx.emit(  and_  (a, b, result))

    _logic_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)


def x86_andn(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1, a.size)

    size = min(a.size, b.size)
    result = ctx.tmp(size)

    ctx.emit(  xor_  (a, imm(mask(size), size), result))
    ctx.emit(  and_  (result, b, result))

    _logic_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)


def x86_not(ctx, i):
    a = operand.get(ctx, i, 0)

    size = a.size
    result = ctx.tmp(size)

    ctx.emit(  xor_  (a, imm(mask(size), size), result))

    operand.set(ctx, i, 0, result)


def x86_or(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1, a.size)

    size = min(a.size, b.size)
    result = ctx.tmp(size)

    ctx.emit(  or_  (a, b, result))

    _logic_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)


def x86_test(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1, a.size)

    size = min(a.size, b.size)
    result = ctx.tmp(size)

    ctx.emit(  and_  (a, b, result))

    _logic_set_flags(ctx, result)


def x86_xor(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1, a.size)

    size = min(a.size, b.size)
    result = ctx.tmp(size)

    ctx.emit(  xor_  (a, b, result))

    _logic_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)