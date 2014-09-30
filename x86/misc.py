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

"""reil.x86.misc - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of basic instructions that I
haven't categorised as anything yet
"""

import reil.error
from reil.shorthand import *

import reil.x86.conditional as conditional
import reil.x86.operand as operand
from reil.x86.utilities import *


def conditional_set(ctx, i, condition):
    c = conditional.condition(ctx, condition)
    operand.set(ctx, i, 0, c)


def _convert(ctx, size):
    a = ctx.accumulator

    prev_a = a
    a = ctx.tmp(size)
    result = ctx.tmp(size * 2)
    high_word = ctx.tmp(size)
    low_word = ctx.tmp(size)

    ctx.emit(  str_  (prev_a, a))
    ctx.emit(  sex_  (a, result))
    ctx.emit(  str_  (result, low_word))
    ctx.emit(  lshr_ (result, imm(size, 8), high_word))
    ctx.emit(  str_  (low_word, ctx.accumulator))
    ctx.emit(  str_  (high_word, ctx.data))


def _convert_2(ctx, size):
    a = ctx.accumulator

    prev_a = a
    a = ctx.tmp(size)
    result = ctx.tmp(size * 2)

    ctx.emit(  str_  (prev_a, a))
    ctx.emit(  sex_  (a, result))
    ctx.emit(  str_  (result, ctx.accumulator))


def x86_bswap(ctx, i):
    a = operand.get(ctx, i, 0)

    if a.size != 32:
        raise pyreil.error.IllegalInstruction(
            'bswap on non 32-bit value!')

    tmp0 = ctx.tmp(32)
    tmp1 = ctx.tmp(32)
    tmp2 = ctx.tmp(32)
    tmp3 = ctx.tmp(32)
    tmp4 = ctx.tmp(32)
    tmp5 = ctx.tmp(32)
    tmp6 = ctx.tmp(32)
    tmp7 = ctx.tmp(32)
    tmp8 = ctx.tmp(32)
    result = ctx.tmp(32)

    bytes = [
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
    ]

    lshift8 = imm(8, 8)
    rshift8 = imm(-8, 8)

    # decompose into bytes
    ctx.emit(  str_  (a, bytes[0]))
    ctx.emit(  bsh_  (a, lshift8, tmp0))
    ctx.emit(  str_  (tmp0, bytes[1]))
    ctx.emit(  bsh_  (tmp0, lshift8, tmp1))
    ctx.emit(  str_  (tmp1, bytes[2]))
    ctx.emit(  bsh_  (tmp1, lshift8, tmp2))
    ctx.emit(  str_  (tmp2, bytes[3]))

    # put back together
    ctx.emit(  str_  (bytes[0], tmp3))
    ctx.emit(  bsh_  (tmp3, rshift8, tmp4))
    ctx.emit(  add_  (bytes[1], tmp4, tmp5))
    ctx.emit(  bsh_  (tmp5, rshift8, tmp6))
    ctx.emit(  add_  (bytes[1], tmp6, tmp7))
    ctx.emit(  bsh_  (tmp7, rshift8, tmp8))
    ctx.emit(  add_  (bytes[1], tmp8, result))

    operand.set(ctx, i, 0, result)


def x86_bswapq(ctx, i):
    a = operand.get(ctx, i, 0)

    if a.size != 64:
        raise pyreil.error.IllegalInstruction(
            'bswapq on non 64-bit value!')

    tmp0 = ctx.tmp(64)
    tmp1 = ctx.tmp(64)
    tmp2 = ctx.tmp(64)
    tmp3 = ctx.tmp(64)
    tmp4 = ctx.tmp(64)
    tmp5 = ctx.tmp(64)
    tmp6 = ctx.tmp(64)
    tmp7 = ctx.tmp(64)
    tmp8 = ctx.tmp(64)
    tmp9 = ctx.tmp(64)
    tmp10 = ctx.tmp(64)
    tmp11 = ctx.tmp(64)
    tmp12 = ctx.tmp(64)
    tmp13 = ctx.tmp(64)
    tmp14 = ctx.tmp(64)
    tmp15 = ctx.tmp(64)
    tmp16 = ctx.tmp(64)
    tmp17 = ctx.tmp(64)
    tmp18 = ctx.tmp(64)
    tmp19 = ctx.tmp(64)
    tmp20 = ctx.tmp(64)
    result = ctx.tmp(64)

    bytes = [
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
        ctx.tmp(8),
    ]

    lshift8 = imm(8, 8)
    rshift8 = imm(-8, 8)

    # decompose into bytes
    ctx.emit(  str_  (a, bytes[0]))
    ctx.emit(  bsh_  (a, lshift8, tmp0))
    ctx.emit(  str_  (tmp0, bytes[1]))
    ctx.emit(  bsh_  (tmp0, lshift8, tmp1))
    ctx.emit(  str_  (tmp1, bytes[2]))
    ctx.emit(  bsh_  (tmp1, lshift8, tmp2))
    ctx.emit(  str_  (tmp2, bytes[3]))
    ctx.emit(  bsh_  (tmp2, lshift8, tmp3))
    ctx.emit(  str_  (tmp3, bytes[4]))
    ctx.emit(  bsh_  (tmp3, lshift8, tmp4))
    ctx.emit(  str_  (tmp4, bytes[5]))
    ctx.emit(  bsh_  (tmp4, lshift8, tmp5))
    ctx.emit(  str_  (tmp5, bytes[6]))
    ctx.emit(  bsh_  (tmp5, lshift8, tmp6))
    ctx.emit(  str_  (tmp6, bytes[7]))

    # put back together
    ctx.emit(  str_  (bytes[0], tmp7))
    ctx.emit(  bsh_  (tmp7, rshift8, tmp8))
    ctx.emit(  add_  (bytes[1], tmp8, tmp9))
    ctx.emit(  bsh_  (tmp9, rshift8, tmp10))
    ctx.emit(  add_  (bytes[1], tmp10, tmp11))
    ctx.emit(  bsh_  (tmp11, rshift8, tmp12))
    ctx.emit(  add_  (bytes[1], tmp12, tmp13))
    ctx.emit(  bsh_  (tmp13, rshift8, tmp14))
    ctx.emit(  add_  (bytes[1], tmp14, tmp15))
    ctx.emit(  bsh_  (tmp15, rshift8, tmp16))
    ctx.emit(  add_  (bytes[1], tmp16, tmp17))
    ctx.emit(  bsh_  (tmp17, rshift8, tmp18))
    ctx.emit(  add_  (bytes[1], tmp18, tmp19))
    ctx.emit(  bsh_  (tmp19, rshift8, tmp20))
    ctx.emit(  add_  (bytes[1], tmp20, result))

    operand.set(ctx, i, 0, result)


def x86_cld(ctx, i):
    ctx.emit(  str_  (imm(0, 8), r('df', 8)))


def x86_cwd(ctx, i):
    _convert(ctx, 16)


def x86_cdq(ctx, i):
    _convert(ctx, 32)


def x86_cqo(ctx, i):
    _convert(ctx, 64)


def x86_cbw(ctx, i):
    _convert_2(ctx, 8)


def x86_cwde(ctx, i):
    _convert_2(ctx, 16)


def x86_cdqe(ctx, i):
    _convert_2(ctx, 32)


def x86_cmpxchg(ctx, i):
    a = ctx.accumulator
    b = operand.get(ctx, i, 0)
    c = operand.get(ctx, i, 1)

    if b.size != a.size:
        prev_a = a
        a = ctx.tmp(b.size)
        ctx.emit(  str_  (prev_a, a))

    tmp0 = ctx.tmp(8)

    ctx.emit(  equ_  (a, b, tmp0))
    ctx.emit(  jcc_  (tmp0, 'equal'))

    ctx.emit('not-equal')
    ctx.emit(  str_  (c, ctx.accumulator))
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('equal')
    operand.set(ctx, i, 0, c)
    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))

    ctx.emit('done')
    ctx.emit(  nop_())


def x86_int(ctx, i):
    ctx.emit(  sys_  (imm(0, 8)))


def x86_nop(ctx, i):
    ctx.emit(  nop_())

def x86_seta(ctx, i):
    """set if above"""
    conditional_set(ctx, i, conditional.A)


def x86_setae(ctx, i):
    """set if above or equal"""
    conditional_set(ctx, i, conditional.AE)


def x86_setb(ctx, i):
    """set if bigger"""
    conditional_set(ctx, i, conditional.B)


def x86_setbe(ctx, i):
    """set if bigger or equal"""
    conditional_set(ctx, i, conditional.BE)


def x86_setcxz(ctx, i):
    """set if cx is zero"""
    conditional_set(ctx, i, conditional.CXZ)


def x86_setecxz(ctx, i):
    """set if ecx is zero"""
    conditional_set(ctx, i, conditional.ECXZ)


def x86_setrcxz(ctx, i):
    """set if rcx is zero"""
    conditional_set(ctx, i, conditional.RCXZ)


def x86_sete(ctx, i):
    """set if equal"""
    conditional_set(ctx, i, conditional.E)


def x86_setg(ctx, i):
    """set if greater"""
    conditional_set(ctx, i, conditional.G)


def x86_setge(ctx, i):
    """set if greater or equal"""
    conditional_set(ctx, i, conditional.GE)


def x86_setl(ctx, i):
    """set if less"""
    conditional_set(ctx, i, conditional.L)


def x86_setle(ctx, i):
    """set if less or equal"""
    conditional_set(ctx, i, conditional.LE)


def x86_setmp(ctx, i):
    """set"""
    conditional_set(ctx, i, conditional.UN)


def x86_setne(ctx, i):
    """set if not equal"""
    conditional_set(ctx, i, conditional.NE)


def x86_setno(ctx, i):
    """set if not overflow"""
    conditional_set(ctx, i, conditional.NO)


def x86_setnp(ctx, i):
    """set if not parity"""

    # TODO: should we just raise an exception? none of the arithmetic
    # instructions set the parity flag correctly because it's so rare

    conditional_set(ctx, i, conditional.NP)


def x86_setns(ctx, i):
    """set if not sign"""
    conditional_set(ctx, i, conditional.NS)


def x86_seto(ctx, i):
    """set if overflow"""
    conditional_set(ctx, i, conditional.O)


def x86_setp(ctx, i):
    """set if parity"""
    conditional_set(ctx, i, conditional.P)


def x86_sets(ctx, i):
    """set if sign"""
    conditional_set(ctx, i, conditional.S)


def x86_sysenter(ctx, i):

    #ctx.emit(  undef_(r('cf', 8)))
    #ctx.emit(  undef_(r('pf', 8)))
    #ctx.emit(  undef_(r('zf', 8)))
    #ctx.emit(  undef_(r('sf', 8)))
    #ctx.emit(  undef_(r('df', 8)))
    #ctx.emit(  undef_(r('of', 8)))

    ctx.emit(  sys_  (imm(1, 8)))


def x86_syscall(ctx, i):

    #ctx.emit(  undef_(r('cf', 8)))
    #ctx.emit(  undef_(r('pf', 8)))
    #ctx.emit(  undef_(r('zf', 8)))
    #ctx.emit(  undef_(r('sf', 8)))
    #ctx.emit(  undef_(r('df', 8)))
    #ctx.emit(  undef_(r('of', 8)))

    ctx.emit(  sys_  (imm(0, 8)))


def x86_xchg(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    tmp0 = ctx.tmp(a.size)

    ctx.emit(  str_  (a, tmp0))

    operand.set(ctx, i, 0, b)
    operand.set(ctx, i, 1, tmp0)


def x86_rdtsc(ctx, i):
    ctx.emit(  nop_  ())