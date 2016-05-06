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

"""reil.x86.bitwise - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of basic instructions that are
all about twiddling bits and bytes
"""

import capstone
import capstone.x86

import reil
import reil.error
from reil.shorthand import *
from reil.utilities import *

import reil.x86.conditional as conditional
import reil.x86.operand as operand
from reil.x86.utilities import *


def _shift_set_flags(ctx, result):

    size = result.size

    sign_result = ctx.tmp(size)

    ctx.emit(  and_  (result, imm(sign_bit(size), size), sign_result))

    # compute sign flag (easy...)
    ctx.emit(  bisnz_(sign_result, r('sf', 8)))

    # compute zero flag (easy...)
    ctx.emit(  bisz_ (result, r('zf', 8)))

    # TODO: compute adjust flag? expensive...

    set_pf(ctx, result)


def _read_bit(ctx, i, base_index, offset_index):
    bit = ctx.tmp(8)

    if operand.is_memory(ctx, i, base_index):
        # nasty case, indexing into in-memory bitstring; offset can be
        # > word_size

        base = operand.get_address(ctx, i, base_index)
        offset = operand.get(ctx, i, offset_index)
        offset_sign = ctx.tmp(8)
        byte_offset = ctx.tmp(base.size)
        tmp0 = ctx.tmp(offset.size)
        tmp1 = ctx.tmp(offset.size)
        tmp2 = ctx.tmp(offset.size)
        byte = ctx.tmp(8)
        bitmask = ctx.tmp(8)

        ctx.emit(  and_  (offset, imm(sign_bit(offset.size), offset.size), tmp0))
        ctx.emit(  bisnz_(tmp0, offset_sign))
        ctx.emit(  and_  (offset, imm(~sign_bit(offset.size), offset.size), tmp1))
        ctx.emit(  div_  (tmp1, imm(8, offset.size), byte_offset))
        ctx.emit(  mod_  (tmp1, imm(8, offset.size), tmp2))

        ctx.emit(  jcc_  (offset_sign, 'negative_offset'))
        ctx.emit(  add_  (base, byte_offset, base))
        ctx.emit(  jcc_  (imm(1, 8), 'base_calculated'))

        ctx.emit('negative_offset')
        ctx.emit(  sub_  (base, byte_offset, base))

        ctx.emit('base_calculated')
        ctx.emit(  ldm_  (base, byte))
        ctx.emit(  lshl_ (imm(1, 8), tmp2, bitmask))
        ctx.emit(  and_  (byte, bitmask, byte))
        ctx.emit(  bisnz_(byte, bit))

    else:
        # simple case, it's a register
        a = operand.get(ctx, i, base_index)
        offset = operand.get(ctx, i, offset_index)
        bitmask = ctx.tmp(a.size)
        tmp0 = ctx.tmp(a.size)

        ctx.emit(  lshl_ (imm(1, a.size), offset, bitmask))
        ctx.emit(  and_  (a, bitmask, tmp0))
        ctx.emit(  bisnz_(tmp0, bit))

    return bit


def _write_bit(ctx, i, base_index, offset_index, bit):
    if operand.is_memory(ctx, i, base_index):
        # nasty case, indexing into in-memory bitstring; offset can be
        # > word_size

        base = operand.get_address(ctx, i, base_index)
        offset = operand.get(ctx, i, offset_index)
        offset_sign = ctx.tmp(8)
        byte_offset = ctx.tmp(base.size)
        tmp0 = ctx.tmp(offset.size)
        byte = ctx.tmp(8)
        bitmask = ctx.tmp(8)

        ctx.emit(  and_  (offset, imm(sign_bit(offset.size), offset.size), tmp0))
        ctx.emit(  bisnz_(tmp0, offset_sign))
        ctx.emit(  and_  (offset, imm(~sign_bit(offset.size), offset.size), offset))
        ctx.emit(  div_  (offset, imm(8, offset.size), byte_offset))
        ctx.emit(  mod_  (offset, imm(8, offset.size), offset))

        ctx.emit(  jcc_  (offset_sign, 'negative_offset'))
        ctx.emit(  add_  (base, byte_offset, base))
        ctx.emit(  jcc_  (imm(1, 8), 'base_calculated'))

        ctx.emit('negative_offset')
        ctx.emit(  sub_  (base, byte_offset, base))

        ctx.emit('base_calculated')
        ctx.emit(  ldm_  (base, byte))
        ctx.emit(  lshl_ (imm(1, 8), offset, bitmask))
        ctx.emit(  xor_  (bitmask, imm(mask(8), 8), bitmask))
        ctx.emit(  and_  (byte, bitmask, byte))
        ctx.emit(  lshl_ (bit, offset, bitmask))
        ctx.emit(  or_   (byte, bit, byte))
        ctx.emit(  stm_  (byte, base))

    else:
        # simple case, it's a register
        a = operand.get(ctx, i, base_index)
        offset = operand.get(ctx, i, offset_index)
        bitmask = ctx.tmp(a.size)
        tmp0 = ctx.tmp(a.size)
        tmp1 = ctx.tmp(a.size)

        ctx.emit(  lshl_ (imm(1, a.size), offset, bitmask))
        ctx.emit(  xor_  (bitmask, imm(mask(a.size), a.size), bitmask))
        ctx.emit(  and_  (a, bitmask, tmp0))
        ctx.emit(  str_  (bit, tmp1))
        ctx.emit(  lshl_ (tmp1, offset, tmp1))
        ctx.emit(  or_   (tmp0, tmp1, tmp1))

        operand.set(ctx, i, base_index, tmp1)


# Instruction Translators


def x86_bextr(ctx, i):
    a = operand.get(ctx, i, 1)
    b = operand.get(ctx, i, 2)

    start = ctx.tmp(8)
    length = ctx.tmp(8)
    mask = ctx.tmp(a.size)
    tmp0 = ctx.tmp(8)
    result = ctx.tmp(a.size)

    ctx.emit(  str_  (b, start))
    ctx.emit(  lshr_ (b, imm(8, 8), length))
    # we are masking off [11111[start + length , start]111111]
    ctx.emit(  sub_  (imm(a.size, a.size), length, tmp0))
    ctx.emit(  lshr_ (imm(mask(a.size), a.size), tmp0, mask))
    #                    [[start + length, start]111111]
    ctx.emit(  add_  (tmp0, start, tmp0))
    ctx.emit(  lshl_ (mask, tmp0, mask))
    #                    [000000000000[start + length, start]]
    ctx.emit(  lshr_ (mask, start, mask))
    # we have our mask   [00000[start + length , start]000000]
    ctx.emit(  and_  (a, mask, result))
    ctx.emit(  lshr_ (result, start, result))

    set_zf(ctx, result)

    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))
    ctx.emit(  undef_(r('af', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('pf', 8)))

    operand.set(ctx, i, 0, result)


def x86_blsi(ctx, i):
    a = operand.get(ctx, i, 1)

    bit = imm(sign_bit(a.size), a.size)
    index = imm(a.size, a.size)

    bit = ctx.tmp(a.size)
    index = ctx.tmp(a.size)
    result = ctx.tmp(a.size)
    tmp0 = ctx.tmp(a.size)

    ctx.emit(  jcc_  (a, 'non-zero'))

    # if a is zero
    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    # set up loop variables and clear zf
    ctx.emit('non-zero')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(0, a.size), index))
    ctx.emit(  str_  (imm(1, a.size), bit))

    # LOOP
    ctx.emit('loop')
    ctx.emit(  and_  (a, bit, tmp0))
    ctx.emit(  jcc_  (tmp0, 'found'))

    # update these for the next one
    ctx.emit(  add_  (index, imm(1, a.size), index))
    ctx.emit(  lshl_ (bit, imm(1, a.size), bit))
    ctx.emit(  jcc_  (imm(1, 8), 'loop'))

    # non-zero case epilogue
    ctx.emit('found')
    ctx.emit(  str_  (imm(1, a.size), result))
    ctx.emit(  lshl_  (result, index, result))

    operand.set(ctx, i, 0, result, clear=True)

    set_sf(ctx, result)
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(1, 8), r('cf', 8)))

    ctx.emit('done')
    ctx.emit(  str_  (imm(0, 8), r('of', 8)))
    ctx.emit(  undef_(r('pf', 8)))
    ctx.emit(  undef_(r('af', 8)))


def x86_blsmsk(ctx, i):
    a = operand.get(ctx, i, 1)

    bit = imm(sign_bit(a.size), a.size)
    index = imm(a.size, a.size)

    bit = ctx.tmp(a.size)
    index = ctx.tmp(a.size)
    result = ctx.tmp(a.size)
    tmp0 = ctx.tmp(a.size)

    ctx.emit(  jcc_  (a, 'non-zero'))

    # if a is zero
    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    # set up loop variables and clear zf
    ctx.emit('non-zero')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(0, a.size), index))
    ctx.emit(  str_  (imm(1, a.size), bit))

    # LOOP
    ctx.emit('loop')
    ctx.emit(  and_  (a, bit, tmp0))
    ctx.emit(  jcc_  (tmp0, 'found'))

    # update these for the next one
    ctx.emit(  add_  (index, imm(1, a.size), index))
    ctx.emit(  lshl_ (bit, imm(1, a.size), bit))
    ctx.emit(  jcc_  (imm(1, 8), 'loop'))

    # non-zero case epilogue
    ctx.emit('found')
    ctx.emit(  str_  (imm(mask(a.size), a.size), result))
    ctx.emit(  lshl_ (result, index, result))
    ctx.emit(  lshr_ (result, index, result))
    ctx.emit(  xor_  (imm(mask(a.size), a.size), result, result))

    operand.set(ctx, i, 0, result, clear=True)

    set_sf(ctx, result)
    ctx.emit(  str_  (imm(1, 8), r('cf', 8)))

    ctx.emit('done')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(0, 8), r('of', 8)))
    ctx.emit(  undef_(r('pf', 8)))
    ctx.emit(  undef_(r('af', 8)))


def x86_blsr(ctx, i):
    a = operand.get(ctx, i, 1)

    bit = imm(sign_bit(a.size), a.size)
    index = imm(a.size, a.size)

    bit = ctx.tmp(a.size)
    index = ctx.tmp(a.size)
    result = ctx.tmp(a.size)
    tmp0 = ctx.tmp(a.size)

    ctx.emit(  jcc_  (a, 'non-zero'))

    # if a is zero
    ctx.emit(  str_  (imm(1, 8), r('cf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    # set up loop variables and clear zf
    ctx.emit('non-zero')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(0, a.size), index))
    ctx.emit(  str_  (imm(1, a.size), bit))

    # LOOP
    ctx.emit('loop')
    ctx.emit(  and_  (a, bit, tmp0))
    ctx.emit(  jcc_  (tmp0, 'found'))

    # update these for the next one
    ctx.emit(  add_  (index, imm(1, a.size), index))
    ctx.emit(  lshl_ (bit, imm(1, a.size), bit))
    ctx.emit(  jcc_  (imm(1, 8), 'loop'))

    # non-zero case epilogue
    ctx.emit('found')
    ctx.emit(  str_  (imm(1, a.size), result))
    ctx.emit(  lshl_ (result, index, result))
    ctx.emit(  xor_  (a, result, result))

    operand.set(ctx, i, 0, result, clear=True)

    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))

    ctx.emit('done')
    set_zf(ctx, result)
    set_sf(ctx, result)
    ctx.emit(  str_  (imm(0, 8), r('of', 8)))
    ctx.emit(  undef_(r('pf', 8)))
    ctx.emit(  undef_(r('af', 8)))


def x86_bsf(ctx, i):
    a = operand.get(ctx, i, 1)

    bit = imm(sign_bit(a.size), a.size)
    index = imm(a.size, a.size)

    bit = ctx.tmp(a.size)
    index = ctx.tmp(a.size)
    tmp0 = ctx.tmp(a.size)

    ctx.emit(  jcc_  (a, 'non-zero'))

    # if a is zero
    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))
    operand.undefine(ctx, i, 0)
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    # set up loop variables and clear zf
    ctx.emit('non-zero')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(0, a.size), index))
    ctx.emit(  str_  (imm(1, a.size), bit))

    # LOOP
    ctx.emit('loop')
    ctx.emit(  and_  (a, bit, tmp0))
    ctx.emit(  jcc_  (tmp0, 'found'))

    # update these for the next one
    ctx.emit(  add_  (index, imm(1, a.size), index))
    ctx.emit(  lshl_ (bit, imm(1, a.size), bit))
    ctx.emit(  jcc_  (imm(1, 8), 'loop'))

    # zero-case epilogue
    ctx.emit('found')
    operand.set(ctx, i, 0, index, clear=True)

    ctx.emit('done')
    ctx.emit(  undef_(r('cf', 8)))
    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('pf', 8)))
    ctx.emit(  undef_(r('af', 8)))


def x86_bsr(ctx, i):
    a = operand.get(ctx, i, 1)

    bit = imm(sign_bit(a.size), a.size)
    index = imm(a.size, a.size)

    bit = ctx.tmp(a.size)
    index = ctx.tmp(a.size)
    tmp0 = ctx.tmp(a.size)

    ctx.emit(  jcc_  (a, 'non-zero'))

    # if a is zero
    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))
    operand.undefine(ctx, i, 0)
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    # set up loop variables and clear zf
    ctx.emit('non-zero')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(a.size - 1, a.size), index))
    ctx.emit(  str_  (imm(sign_bit(a.size), a.size), bit))

    # LOOP
    ctx.emit('loop')
    ctx.emit(  and_  (a, bit, tmp0))
    ctx.emit(  jcc_  (tmp0, 'found'))

    # update these for the next one
    ctx.emit(  sub_  (index, imm(1, a.size), index))
    ctx.emit(  lshr_ (bit, imm(1, a.size), bit))
    ctx.emit(  jcc_  (imm(1, 8), 'loop'))

    # zero-case epilogue
    ctx.emit('found')
    operand.set(ctx, i, 0, index, clear=True)

    ctx.emit('done')
    ctx.emit(  undef_(r('cf', 8)))
    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('pf', 8)))
    ctx.emit(  undef_(r('af', 8)))


def x86_bt(ctx, i):
    bit = _read_bit(ctx, i, 0, 1)

    ctx.emit(  str_  (bit, r('cf', 8)))


def x86_btc(ctx, i):
    bit = _read_bit(ctx, i, 0, 1)

    ctx.emit(  str_  (bit, r('cf', 8)))
    ctx.emit(  bisz_ (bit, bit))

    _write_bit(ctx, i, 0, 1, bit)


def x86_btr(ctx, i):
    bit = _read_bit(ctx, i, 0, 1)

    ctx.emit(  str_  (bit, r('cf', 8)))

    _write_bit(ctx, i, 0, 1, imm(0, 8))


def x86_bts(ctx, i):
    bit = _read_bit(ctx, i, 0, 1)

    ctx.emit(  str_  (bit, r('cf', 8)))

    _write_bit(ctx, i, 0, 1, imm(1, 8))


def x86_bzhi(ctx, i):
    a = operand.get(ctx, i, 1)
    b = operand.get(ctx, i, 2)

    result = ctx.tmp(a.size)
    index = ctx.tmp(a.size)
    tmp0 = ctx.tmp(a.size * 2)

    ctx.emit(  mod_  (b, imm(a.size - 1, a.size), index))
    ctx.emit(  lshl_ (a, index, result))
    ctx.emit(  lshr_ (result, index, result))

    ctx.emit(  sub_  (b, imm(a.size - 1, a.size), tmp0))
    ctx.emit(  and_  (tmp0, imm(sign_bit(a.size * 2), a.size * 2), tmp0))
    ctx.emit(  bisnz_(tmp0, r('cf', 8)))

    set_zf(ctx, result)
    set_pf(ctx, result)

    ctx.emit(  str_  (imm(0, 8), r('of', 8)))

    ctx.emit(  undef_(r('pf', 8)))
    ctx.emit(  undef_(r('af', 8)))


def x86_lzcnt(ctx, i):
    a = operand.get(ctx, i, 1)

    bit = imm(1, a.size)
    index = imm(0, a.size)

    bit = ctx.tmp(a.size)
    index = ctx.tmp(a.size)
    tmp0 = ctx.tmp(a.size)

    ctx.emit(  jcc_  (a, 'non-zero'))

    # if a is zero
    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))
    operand.set(i, 0, imm(a.size, a.size))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    # set up loop variables and clear zf
    ctx.emit('non-zero')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  str_  (imm(0, a.size), index))
    ctx.emit(  str_  (imm(1, a.size), bit))

    # LOOP
    ctx.emit('loop')
    ctx.emit(  and_  (a, bit, tmp0))
    ctx.emit(  jcc_  (tmp0, 'found'))

    # update these for the next one
    ctx.emit(  add_  (index, imm(1, a.size), index))
    ctx.emit(  lshr_ (bit, imm(1, a.size), bit))
    ctx.emit(  jcc_  (imm(1, 8), 'loop'))

    # zero-case epilogue
    ctx.emit('found')
    operand.set(ctx, i, 0, index, clear=True)

    ctx.emit('done')
    ctx.emit(  undef_(r('cf', 8)))
    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('pf', 8)))
    ctx.emit(  undef_(r('af', 8)))


def x86_rol(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    max_shift = a.size-1

    size = a.size
    tmp0 = ctx.tmp(size)
    tmp1 = ctx.tmp(8)
    tmp2 = ctx.tmp(size * 2)
    tmp3 = ctx.tmp(size * 2)
    tmp4 = ctx.tmp(size)
    tmp5 = ctx.tmp(size * 2)
    tmp6 = ctx.tmp(size * 2)
    tmp7 = ctx.tmp(size)
    tmp8 = ctx.tmp(size)
    result = ctx.tmp(size)

    # the rotate amount is truncated at word_size - 1
    ctx.emit(  and_  (b, imm(max_shift, size), tmp0))

    # zero rotate doesn't affect flags
    ctx.emit(  bisz_ (tmp0, tmp1))
    ctx.emit(  jcc_  (tmp1, 'zero_rotate'))

    # zero extend
    ctx.emit(  str_  (a, tmp2))

    # left shift by the correct amount
    ctx.emit(  lshl_ (tmp2, tmp0, tmp3))

    # truncate to get first half of result
    ctx.emit(  str_  (tmp3, tmp4))

    # shift out then truncate to get second half of result
    ctx.emit(  lshr_ (tmp3, imm(max_shift+1, size * 2), tmp5))
    ctx.emit(  str_  (tmp5, tmp6))

    # or both halves of the result
    ctx.emit(  or_   (tmp4, tmp6, result))

    # compute carry flag (last bit that was shifted across)
    ctx.emit(  and_  (result, imm(1, size), tmp7))
    ctx.emit(  bisnz_(tmp7, r('cf', 8)))

    if isinstance(b, reil.ImmediateOperand) and b.value == 1:
        # overflow flag is msb of input ^ msb output
        tmp9 = ctx.tmp(size)
        ctx.emit(  and_  (a, imm(sign_bit(size), size), tmp8))
        ctx.emit(  xor_  (tmp8, tmp7, tmp8))
        ctx.emit(  bisnz_(tmp8, r('of', 8)))
    else:
        ctx.emit(  undef_(r('of', 8)))

    operand.set(ctx, i, 0, result)

    ctx.emit(  'zero_rotate')
    ctx.emit(  nop_())


def x86_ror(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    max_shift = a.size-1

    size = a.size
    tmp0 = ctx.tmp(size)
    tmp1 = ctx.tmp(8)
    tmp2 = ctx.tmp(size * 2)
    tmp3 = ctx.tmp(size * 2)
    tmp4 = ctx.tmp(size * 2)
    tmp5 = ctx.tmp(size)
    tmp6 = ctx.tmp(size * 2)
    tmp7 = ctx.tmp(size)
    tmp8 = ctx.tmp(size)
    result = ctx.tmp(size)

    # the rotate amount is truncated at word_size - 1
    ctx.emit(  and_  (b, imm(max_shift, size), tmp0))

    # zero rotate doesn't affect flags
    ctx.emit(  bisz_ (tmp0, tmp1))
    ctx.emit(  jcc_  (tmp1, 'zero_rotate'))

    # zero extend
    ctx.emit(  str_  (a, tmp2))

    # left shift all the way
    ctx.emit(  lshl_ (tmp2, imm(max_shift+1, size * 2), tmp3))

    # right shift by the correct amount
    ctx.emit(  lshr_ (tmp3, tmp0, tmp4))

    # truncate to get first half of result
    ctx.emit(  str_  (tmp4, tmp5))

    # shift out then truncate to get second half of result
    ctx.emit(  lshr_ (tmp4, imm(max_shift+1, size * 2), tmp6))
    ctx.emit(  str_  (tmp6, tmp7))

    # or both halves of the result
    ctx.emit(  or_   (tmp5, tmp7, result))

    # compute carry flag (last bit that was shifted across)
    ctx.emit(  and_  (result, imm(sign_bit(size), size), tmp8))
    ctx.emit(  bisnz_(tmp8, r('cf', 8)))

    if isinstance(b, reil.ImmediateOperand) and b.value == 1:
        # overflow flag is msb of input ^ msb output
        tmp9 = ctx.tmp(size)
        ctx.emit(  and_  (a, imm(sign_bit(size), size), tmp9))
        ctx.emit(  xor_  (tmp9, tmp8, tmp9))
        ctx.emit(  bisnz_(tmp9, r('of', 8)))
    else:
        ctx.emit(  undef_(r('of', 8)))

    operand.set(ctx, i, 0, result)

    ctx.emit(  'zero_rotate')
    ctx.emit(  nop_())



def x86_sar(ctx, i):
    a = operand.get(ctx, i, 0)

    if len(i.operands) == 1:
        if i.mnemonic.endswith('1'):
            b = imm(1, a.size)
        else:
            b = ctx.counter
    else:
        b = operand.get(ctx, i, 1)

    max_shift = a.size-1

    size = a.size
    tmp0 = ctx.tmp(size)
    tmp1 = ctx.tmp(size * 2)
    tmp2 = ctx.tmp(size * 2)
    tmp3 = ctx.tmp(size * 2)
    tmp4 = ctx.tmp(size)
    tmp5 = ctx.tmp(size * 2)
    result = ctx.tmp(a.size)

    # the shift amount is truncated at word_size - 1
    ctx.emit(  and_  (b, imm(max_shift, size), tmp0))

    # zero extend
    ctx.emit(  str_  (a, tmp1))

    # left shift all the way
    ctx.emit(  lshl_ (tmp1, imm(max_shift+1, size * 2), tmp2))

    # right shift by the correct amount
    ctx.emit(  ashr_ (tmp2, tmp0, tmp3))

    # save off the first bit that is going to be lost
    ctx.emit(  and_  (tmp3, imm(sign_bit(size), size * 2), tmp4))

    # shift out then truncate to get second half of result
    ctx.emit(  ashr_ (tmp3, imm(max_shift+1, size * 2), tmp5))
    ctx.emit(  str_  (tmp5, result))

    # set sign flag
    ctx.emit(  bisnz_(tmp4, r('cf', 8)))

    # overflow flag is always 0
    ctx.emit(  str_  (imm(0, 8), r('of', 8)))

    _shift_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)


def x86_shl(ctx, i):
    a = operand.get(ctx, i, 0)

    if len(i.operands) == 1:
        if i.mnemonic.endswith('1'):
            b = imm(1, a.size)
        else:
            b = ctx.counter
    else:
        b = operand.get(ctx, i, 1)

    max_shift = a.size-1

    size = a.size
    tmp0 = ctx.tmp(size)
    tmp1 = ctx.tmp(8)
    tmp2 = ctx.tmp(size * 2)
    tmp3 = ctx.tmp(size * 2)
    tmp4 = ctx.tmp(size * 2)
    tmp5 = ctx.tmp(8)
    tmp6 = ctx.tmp(size)
    tmp7 = ctx.tmp(8)
    result = ctx.tmp(size)

    ctx.emit(  and_  (b, imm(max_shift, size), tmp0))

    # zero shift doesn't affect flags
    ctx.emit(  bisz_ (tmp0, tmp1))
    ctx.emit(  jcc_  (tmp1, 'zero_shift'))

    # zero extend
    ctx.emit(  str_  (a, tmp2))

    # left shift by the correct amount
    ctx.emit(  lshl_ (tmp2, tmp0, tmp3))

    # truncate to get result
    ctx.emit(  str_  (tmp3, result))

    # compute carry flag
    ctx.emit(  and_  (tmp3, imm(carry_bit(size), size * 2), tmp4))
    ctx.emit(  bisnz_(tmp4, r('cf', 8)))

    ctx.emit(  equ_  (tmp0, imm(1, size), tmp5))
    ctx.emit(  bisz_ (tmp5, tmp5))
    ctx.emit(  jcc_  (tmp5, 'no_overflow_flag'))

    # compute overflow flag
    ctx.emit(  and_  (result, imm(sign_bit(size), size), tmp6))
    ctx.emit(  bisnz_(tmp6, tmp7))
    ctx.emit(  xor_  (r('cf', 8), tmp7, r('of', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'overflow_flag_done'))

    ctx.emit('no_overflow_flag')
    ctx.emit(  undef_(r('of', 8)))

    ctx.emit('overflow_flag_done')

    _shift_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)

    ctx.emit(  'zero_shift')
    ctx.emit(  nop_())


def x86_shr(ctx, i):
    a = operand.get(ctx, i, 0)

    if len(i.operands) == 1:
        if i.mnemonic.endswith('1'):
            b = imm(1, a.size)
        else:
            b = ctx.counter
    else:
        b = operand.get(ctx, i, 1)

    max_shift = a.size-1

    size = a.size
    tmp0 = ctx.tmp(size)
    tmp1 = ctx.tmp(8)
    tmp2 = ctx.tmp(size * 2)
    tmp3 = ctx.tmp(size * 2)
    tmp4 = ctx.tmp(size * 2)
    tmp5 = ctx.tmp(size * 2)
    tmp6 = ctx.tmp(8)
    tmp7 = ctx.tmp(size)
    tmp8 = ctx.tmp(size)
    result = ctx.tmp(size)

    # the shift amount is truncated at word_size - 1
    ctx.emit(  and_  (b, imm(max_shift, size), tmp0))

    # zero shift doesn't affect flags
    ctx.emit(  bisz_ (tmp0, tmp1))
    ctx.emit(  jcc_  (tmp1, 'zero_shift'))

    # zero extend
    ctx.emit(  str_  (a, tmp2))

    # left shift all the way
    ctx.emit(  lshl_ (tmp2, imm(max_shift+1, size * 2), tmp3))

    # right shift by the correct amount
    ctx.emit(  lshr_ (tmp3, tmp0, tmp4))

    # shift out then truncate to get second half of result
    ctx.emit(  lshr_ (tmp4, imm(max_shift+1, size * 2), tmp5))
    ctx.emit(  str_  (tmp5, result))

    ctx.emit(  equ_  (tmp0, imm(1, size), tmp6))
    ctx.emit(  bisz_ (tmp6, tmp6))
    ctx.emit(  jcc_  (tmp6, 'no_overflow_flag'))

    # compute overflow flag
    ctx.emit(  and_  (a, imm(sign_bit(size), size), tmp7))
    ctx.emit(  bisnz_(tmp7, r('of', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'overflow_flag_done'))

    ctx.emit('no_overflow_flag')
    ctx.emit(  undef_(r('of', 8)))

    ctx.emit('overflow_flag_done')

    # compute carry flag (last bit to be shifted out)
    ctx.emit(  and_  (tmp4, imm(sign_bit(size), size), tmp8))
    ctx.emit(  bisnz_(tmp8, r('cf', 8)))

    _shift_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)

    ctx.emit(  'zero_shift')
    ctx.emit(  nop_())


def x86_shrd(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    if len(i.operands) == 2:
        c = ctx.counter
    else:
        c = operand.get(ctx, i, 2)

    size = a.size
    max_shift = size - 1

    tmp0 = ctx.tmp(size)
    tmp1 = ctx.tmp(size * 2)
    result = ctx.tmp(size)

    # the shift amount is truncated at word_size - 1
    ctx.emit(  and_  (c, imm(max_shift, size), tmp0))

    # make a register double the size of the operands containing b a
    ctx.emit(  str_  (b, tmp1))
    ctx.emit(  lshl_ (tmp1, imm(size // 8, 8), tmp1))
    ctx.emit(  or_   (tmp1, a, tmp1))

    # now shift right by the desired amount
    ctx.emit(  lshr_ (tmp1, tmp0, tmp1))

    # and truncate into result
    ctx.emit(  str_  (tmp1, result))

    # TODO: flags properly

    _shift_set_flags(ctx, result)

    operand.set(ctx, i, 0, result)
