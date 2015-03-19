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

"""reil.x86.utilities - x86 and x86_64 translation utility functions.

This module contains all the silly little utility functions that didn't
belong anywhere else.
"""

import reil.definitions as reil
from reil.shorthand import *

def carry_bit(size):
    """The mask required for the carry bit on a computation with a
    result of bit-size 'size'.
    """

    return 1 << size


def sign_bit(size):
    """The mask required for the sign bit of a value with bit-size
    'size'.
    """

    return 1 << (size - 1)


def mask(size):
    """The basic bitmask to extract the value of bit-size 'size'."""

    if size == 8:
        return 0xff
    elif size == 16:
        return 0xffff
    elif size == 32:
        return 0xffffffff
    elif size == 64:
        return 0xffffffffffffffff
    elif size == 128:
        return 0xffffffffffffffffffffffffffffffff


def set_pf(ctx, result):
    """compute parity flag (parity of lsb)"""

    tmp0 = ctx.tmp(8)
    tmp1 = ctx.tmp(8)
    tmp2 = ctx.tmp(16)

    # see http://www-graphics.stanford.edu/~seander/bithacks.html#ParityParallel

    ctx.emit(  str_  (result, tmp0))
    ctx.emit(  lshr_ (tmp0, imm(4, 8), tmp1))
    ctx.emit(  xor_  (tmp0, tmp1, tmp0))
    ctx.emit(  and_  (tmp0, imm(0xf, 8), tmp1))
    ctx.emit(  lshr_ (imm(0x9669, 16), tmp1, tmp2))
    ctx.emit(  and_  (tmp2, imm(1, 8), r('pf', 8)))


def set_sf(ctx, result):
    """compute sign flag based on size of input result"""
    ctx.emit(  and_  (result, imm(sign_bit(result.size), result.size), r('sf', 8)))


def set_zf(ctx, result):
    """compute zero flag"""
    ctx.emit(  bisz_ (result, r('zf', 8)))


def unpack(ctx, value, size):
    """Unpack value into components of size."""

    parts = []

    tmp0 = value
    for i in range(0, value.size // size):
        part = ctx.tmp(size)

        tmp1 = tmp0
        tmp0 = ctx.tmp(value.size)

        ctx.emit(  str_  (tmp1, part))
        ctx.emit(  lshr_ (tmp1, imm(size, 8), tmp0))

        parts.append(part)

    return parts


def pack(ctx, parts):
    """Pack parts into a single value."""

    parts.reverse()

    size = len(parts) * parts[0].size

    value = imm(0, size)

    for part in parts:
        prev_value = value
        tmp0 = ctx.tmp(size)
        value = ctx.tmp(size)

        ctx.emit(  lshl_ (prev_value, imm(part.size, 8), tmp0))
        ctx.emit(  add_  (part, tmp0, value))

    return value