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

"""reil.x86.sse - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of instructions that belong to
the streaming-simd extensions
"""

import itertools

import capstone
import capstone.x86

import reil.error
from reil.shorthand import *

import reil.x86.conditional as conditional
import reil.x86.memory as memory
import reil.x86.operand as operand
from reil.x86.utilities import *

def unpack(ctx, value, size):
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


x86_movaps = memory.x86_mov
x86_movd = memory.x86_mov
x86_movdqa = memory.x86_mov
x86_vmovdqa = memory.x86_mov
x86_movdqu = memory.x86_mov
x86_vmovdqu = memory.x86_mov
x86_movups = memory.x86_mov


def x86_movhpd(ctx, i):
    a = operand.get(ctx, i, 0)
    value = operand.get(ctx, i, 1)
    tmp0 = ctx.tmp(a.size)
    tmp1 = ctx.tmp(a.size)

    ctx.emit(  and_  (a, imm(0x0000000000000000ffffffffffffffff, 128), tmp0))
    ctx.emit(  str_  (value, tmp1))
    ctx.emit(  lshl_ (tmp1, imm(64, 8), tmp1))
    ctx.emit(  or_   (tmp0, tmp1, tmp0))

    operand.set(ctx, i, 0, tmp0)


def x86_movlpd(ctx, i):
    a = operand.get(ctx, i, 0)
    value = operand.get(ctx, i, 1)
    tmp0 = ctx.tmp(a.size)
    tmp1 = ctx.tmp(a.size)
    ctx.emit(  and_  (a, imm(0xffffffffffffffff0000000000000000, 128), tmp0))
    ctx.emit(  or_   (tmp0, value, tmp0))

    operand.set(ctx, i, 0, tmp0)


def x86_movq(ctx, i):
    value = None

    dst = operand.get(ctx, i, 0)
    value = operand.get(ctx, i, 1)

    operand.set(ctx, i, 0, value, clear=True, sign_extend=False)


def x86_palignr(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    # this is always an immediate operand
    shift = operand.get(ctx, i, 2).value * 8

    if a.size == 64:
        tmp0 = pack(ctx, i, [a, b])
    else:
        tmp0 = ctx.tmp(256)
        tmp1 = ctx.tmp(256)
        ctx.emit(  str_  (a, tmp0))
        ctx.emit(  str_  (b, tmp1))
        ctx.emit(  lshl_ (tmp0, imm(128, 8), tmp0))
        ctx.emit(  or_   (tmp0, tmp1, tmp0))

    result = ctx.tmp(tmp0.size)

    ctx.emit(  lshr_ (tmp0, imm(shift, 32), result))

    operand.set(ctx, i, 0, result)


def x86_pcmpeqb(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    a_bytes = unpack(ctx, a, 8)
    b_bytes = unpack(ctx, b, 8)

    bytes = []
    for (a_byte, b_byte) in zip(a_bytes, b_bytes):
        tmp0 = ctx.tmp(8)
        tmp1 = ctx.tmp(8)

        ctx.emit(  equ_  (a_byte, b_byte, tmp0))
        ctx.emit(  mul_  (tmp0, imm(0xff, 8), tmp1))

        bytes.append(tmp1)

    value = pack(ctx, bytes)

    operand.set(ctx, i, 0, value)


def x86_pmovmskb(ctx, i):
    a = operand.get(ctx, i, 1)
    a_bytes = unpack(ctx, a, 8)

    bits = []
    for a_byte in a_bytes:
        tmp0 = ctx.tmp(8)
        ctx.emit(  and_  (a_byte, imm(sign_bit(8), 8), tmp0))
        ctx.emit(  bisnz_(tmp0, tmp0))
        bits.append(tmp0)

    bits.reverse()

    value = imm(0, a.size // 8)
    for bit in bits:
        prev_value = value
        tmp0 = ctx.tmp(a.size // 8)
        value = ctx.tmp(a.size // 8)
        ctx.emit(  lshl_  (prev_value, imm(1, 8), tmp0))
        ctx.emit(  add_   (tmp0, bit, value))

    operand.set(ctx, i, 0, value, clear=True)


def x86_por(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    size = min(a.size, b.size)
    value = ctx.tmp(size)

    ctx.emit(  or_  (a, b, value))

    operand.set(ctx, i, 0, value)


def x86_pshufd(ctx, i):
    src = operand.get(ctx, i, 1)
    order = operand.get(ctx, i, 2)

    value = imm(0, 128)

    for j in range(0, 4):

        prev_order = order
        order = ctx.tmp(8)
        prev_value = value
        value = ctx.tmp(128)

        tmp0 = ctx.tmp(128)
        tmp1 = ctx.tmp(8)
        tmp2 = ctx.tmp(32)
        tmp3 = ctx.tmp(128)
        tmp4 = ctx.tmp(32)
        tmp5 = ctx.tmp(128)
        tmp6 = ctx.tmp(128)

        ctx.emit(  lshr_ (prev_order, imm(2, 8), order))
        ctx.emit(  and_  (prev_order, imm(0b00000011, 8), tmp1))
        ctx.emit(  mul_  (tmp1, imm(32, 32), tmp2))
        ctx.emit(  lshr_ (src, tmp2, tmp3))
        ctx.emit(  str_  (tmp3, tmp4))
        ctx.emit(  str_  (tmp4, tmp5))
        ctx.emit(  lshl_ (tmp5, imm(j * 32, 8), tmp6))
        ctx.emit(  add_  (tmp6, prev_value, value))

    operand.set(ctx, i, 0, value)


def x86_pslldq(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)
    result = ctx.tmp(a.size)

    shift = min(b.value, 16)

    # left shift by the correct amount
    ctx.emit(  lshl_ (a, imm(shift * 8, 8), result))

    operand.set(ctx, i, 0, result)


def _x86_psub(ctx, i, part_size):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    size = min(a.size, b.size)
    part_count = size // part_size

    a_parts = unpack(ctx, a, part_size)[:part_count]
    if a == b:
        b_parts = a_parts
    else:
        b_parts = unpack(ctx, b, part_size)[:part_count]

    parts = []
    for j in range(0, part_count):
        tmp = ctx.tmp(part_size)
        ctx.emit(  sub_  (a_parts[j], b_parts[j], tmp))
        parts.append(tmp)

    value = pack(ctx, parts)

    operand.set(ctx, i, 0, value)


def x86_psubb(ctx, i):
    _x86_psub(ctx, i, 8)


def x86_psubw(ctx, i):
    _x86_psub(ctx, i, 16)


def x86_psubd(ctx, i):
    _x86_psub(ctx, i, 32)


def x86_psubq(ctx, i):
    _x86_psub(ctx, i, 64)


def _x86_punpckl(ctx, i, part_size):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    size = min(a.size, b.size)
    part_count = size // (part_size * 2)

    a_parts = unpack(ctx, a, part_size)[:part_count]
    if a == b:
        b_parts = a_parts
    else:
        b_parts = unpack(ctx, b, part_size)[:part_count]

    parts = []
    for j in range(0, part_count):
        parts.append(a_parts[j])
        parts.append(b_parts[j])

    value = pack(ctx, parts)

    operand.set(ctx, i, 0, value)


def x86_punpcklbw(ctx, i):
    _x86_punpckl(ctx, i, 8)


def x86_punpcklwd(ctx, i):
    _x86_punpckl(ctx, i, 16)


def x86_punpckldq(ctx, i):
    _x86_punpckl(ctx, i, 32)


def x86_punpcklqdq(ctx, i):
    _x86_punpckl(ctx, i, 64)


def x86_pxor(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    size = min(a.size, b.size)
    value = ctx.tmp(size)

    ctx.emit(  xor_  (a, b, value))

    operand.set(ctx, i, 0, value)