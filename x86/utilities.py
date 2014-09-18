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

import pyreil.reil as reil
from pyreil.shorthand import *

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


