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

"""reil.x86.arithmetic - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of basic arithmetic instructions
such as add, mul, div
"""

import reil.error
from reil.shorthand import *
from reil.utilities import *

import reil.x86.conditional as conditional
import reil.x86.operand as operand
from reil.x86.utilities import *


# Helpers

def _arithmetic_set_flags(ctx, sign_a, sign_b, result, cf=True):
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
    ctx.emit(  bisnz_(tmp2, r('of', 8)))

    # compute sign flag (easy...)
    ctx.emit(  bisnz_(sign_result, r('sf', 8)))

    # compute zero flag (easy...)
    ctx.emit(  and_  (result, imm(mask(size), size), tmp3))
    ctx.emit(  bisz_ (tmp3, r('zf', 8)))

    # TODO: compute adjust flag? expensive...

    if cf:
        # compute carry flag
        ctx.emit(  and_  (result, imm(carry_bit(size), result.size), tmp4))
        ctx.emit(  bisnz_(tmp4, r('cf', 8)))

    set_pf(ctx, result)


def _add_set_flags(ctx, a, b, result, cf=True):
    size = a.size

    sign_a = ctx.tmp(size)
    sign_b = ctx.tmp(size)

    ctx.emit(  and_  (a, imm(sign_bit(size), size), sign_a))
    ctx.emit(  and_  (b, imm(sign_bit(size), size), sign_b))

    _arithmetic_set_flags(ctx, sign_a, sign_b, result, cf)


def _imul_set_flags(ctx, result):
    tmp0 = ctx.tmp(result.size)

    ctx.emit(  and_  (result,
                      imm(mask(result.size) ^ mask(result.size // 2), result.size),
                      tmp0))

    ctx.emit(  bisnz_(tmp0, r('cf', 8)))
    ctx.emit(  bisnz_(tmp0, r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('zf', 8)))

    set_pf(ctx, result)


def _sub_set_flags(ctx, a, b, result, cf=True):
    size = a.size

    tmp0 = ctx.tmp(size)

    sign_a = ctx.tmp(size)
    sign_b = ctx.tmp(size)

    ctx.emit(  and_  (a, imm(sign_bit(size), size), sign_a))
    ctx.emit(  xor_  (b, imm(sign_bit(size), size), tmp0))
    ctx.emit(  and_  (tmp0, imm(sign_bit(size), size), sign_b))

    _arithmetic_set_flags(ctx, sign_a, sign_b, result, cf)


def _sign_extend(ctx, a, b):
    if b.size < a.size:
        prev_b = b
        b = ctx.tmp(a.size)
        ctx.emit(  sex_  (prev_b, b))

    return b

# Instruction Translators

def x86_adc(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  add_  (a, b, result))
    ctx.emit(  add_  (result, r('cf', 8), result))

    _add_set_flags(ctx, a, b, result)

    operand.set(ctx, i, 0, result)


def x86_adcx(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)
    tmp0 = ctx.tmp(a.size * 2)

    ctx.emit(  add_  (a, b, result))
    ctx.emit(  add_  (result, r('cf', 8), result))

    # only set carry flag
    ctx.emit(  and_  (result, imm(carry_bit(a.size), result.size), tmp0))
    ctx.emit(  bisnz_(tmp0, r('cf', 8)))

    operand.set(ctx, i, 0, result)


def x86_adox(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)
    tmp0 = ctx.tmp(a.size * 2)

    ctx.emit(  add_  (a, b, result))
    ctx.emit(  add_  (result, r('of', 8), result))

    # only set carry flag
    ctx.emit(  and_  (result, imm(carry_bit(a.size), result.size), tmp0))
    ctx.emit(  bisnz_(tmp0, r('of', 8)))

    operand.set(ctx, i, 0, result)


def x86_add(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  add_  (a, b, result))

    _add_set_flags(ctx, a, b, result)

    operand.set(ctx, i, 0, result)


def x86_cmp(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    # HACK: operand.get isn't handling this well for the byte -0x80 provided by capstone
    # that's fair, because let's be honest, that's just retarded output from the disassembler
    if b.size > a.size:
        prev_b = b
        b = ctx.tmp(a.size)
        ctx.emit(  str_  (prev_b, b))

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  sub_  (a, b, result))

    _sub_set_flags(ctx, a, b, result)


def x86_div(ctx, i):
    if len(i.operands) > 0:
        divisor = operand.get(ctx, i, 0)
    else:
        divisor = ctx.counter

    # TODO: integer divide by 0

    if divisor.size == 8:
        # dividend = ax
        dividend = r(ctx.accumulator.name, 16)
        quotient = ctx.tmp(divisor.size // 2)
        remainder = ctx.tmp(divisor.size // 2)
    else:
        # dividend = dx:ax, edx:eax, rdx:rax
        a = r(ctx.accumulator.name, divisor.size)
        b = r(ctx.data.name, divisor.size)

        dividend = ctx.tmp(divisor.size * 2)
        quotient = r(ctx.accumulator.name, divisor.size)
        remainder = r(ctx.data.name, divisor.size)

        ctx.emit(  str_  (b, dividend))
        ctx.emit(  lshl_ (dividend, imm(divisor.size, 8), dividend))
        ctx.emit(  or_  (a, dividend, dividend))

    ctx.emit(  div_  (dividend, divisor, quotient))
    ctx.emit(  mod_  (dividend, divisor, remainder))

    # TODO: implement checking for overflow

    if divisor.size == 8:
        # result goes in ax

        result = r(ctx.accumulator.name, 16)
        ctx.emit(  str_  (remainder, result))
        ctx.emit(  lshl_ (result, imm(divisor.size, 8), result))
        ctx.emit(  or_   (quotient, result, result))
    else:
        # quotient goes in *ax, remainder goes in *dx
        ctx.emit(  str_  (quotient, ctx.accumulator))
        ctx.emit(  str_  (remainder, ctx.data))

    ctx.emit(  undef_(r('cf', 8)))
    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('zf', 8)))
    ctx.emit(  undef_(r('af', 8)))
    ctx.emit(  undef_(r('pf', 8)))


def x86_dec(ctx, i):
    a = operand.get(ctx, i, 0)

    b = imm(1, a.size)
    result = ctx.tmp(a.size * 2)

    ctx.emit(  sub_  (a, b, result))

    _sub_set_flags(ctx, a, b, result, cf=False)

    operand.set(ctx, i, 0, result)


def x86_idiv(ctx, i):
    divisor = operand.get(ctx, i, 0)
    dividend = ctx.tmp(divisor.size * 2)

    if divisor.size == 8:
        # dividend is ax
        ctx.emit(  str_  (ctx.accumulator, dividend))

    else:
        # dividend is dx:ax, edx:eax, rdx:rax
        dividend_lo = ctx.tmp(divisor.size)
        dividend_hi = ctx.tmp(divisor.size)

        ctx.emit(  str_  (ctx.accumulator, dividend_lo))
        ctx.emit(  str_  (ctx.data, dividend_hi))
        ctx.emit(  lshl_ (dividend_hi, imm(divisor.size, 8), dividend))
        ctx.emit(  or_   (dividend, dividend_lo, dividend))

    quotient = ctx.tmp(divisor.size)
    remainder = ctx.tmp(divisor.size)

    # TODO: implement checking for overflow

    # TODO: also is a signed divide/modulus different to unsigned, or is it
    # just a question of the error cases being different? consider... testcases
    # so far suggest that it is the same, but that is just from program traces
    # not exhaustive proof.

    ctx.emit(  sdiv_ (dividend, divisor, quotient))
    ctx.emit(  mod_  (dividend, divisor, remainder))

    # compute sign of remainder
    tmp = ctx.tmp(dividend.size)
    ctx.emit(  and_  (dividend, imm(sign_bit(dividend.size), dividend.size), tmp))
    ctx.emit(  bisz_ (tmp, tmp))
    ctx.emit(  jcc_  (tmp, 'positive'))

    # remainder is negative


    # remainder is positive, nothing to do
    ctx.emit('positive')

    if divisor.size == 8:
        # result goes in ax

        result = r(ctx.accumulator.name, 16)
        ctx.emit(  str_  (remainder, result))
        ctx.emit(  lshl_ (result, imm(divisor.size, 8), result))
        ctx.emit(  or_   (quotient, result, result))
    else:
        # quotient goes in *ax, remainder goes in *dx
        ctx.emit(  str_  (quotient, ctx.accumulator))
        ctx.emit(  str_  (remainder, ctx.data))

    ctx.emit(  undef_(r('cf', 8)))
    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('zf', 8)))
    ctx.emit(  undef_(r('af', 8)))
    ctx.emit(  undef_(r('pf', 8)))




def x86_imul(ctx, i):
    if len(i.operands) == 1:
        # single operand form
        b = operand.get(ctx, i, 0)

        if b.size == 64:
          a_reg = 'rax'
          b_reg = 'rdx'
        elif b.size == 32:
          a_reg = 'eax'
          b_reg = 'edx'
        elif b.size == 16:
          a_reg = 'ax'
          b_reg = 'dx'
        elif b.size == 8:
          a_reg = 'al'
          b_reg = 'ah'

        a = operand.get_register(ctx, i, a_reg)

        result = ctx.tmp(b.size * 2)
        result_value = ctx.tmp(b.size)

        ctx.emit(  mul_  (a, b, result))

        ctx.emit(  str_  (result, result_value))
        operand.set_register(ctx, i, a_reg, result_value)
        ctx.emit(  lshr_ (result, imm(b.size, 8), result_value))
        operand.set_register(ctx, i, b_reg, result_value)

        _imul_set_flags(ctx, result)

    elif len(i.operands) == 2:
        # double operand form
        a = operand.get(ctx, i, 0)
        b = operand.get(ctx, i, 1)

        result = ctx.tmp(a.size * 2)

        ctx.emit(  mul_  (a, b, result))

        operand.set(ctx, i, 0, result)

        _imul_set_flags(ctx, result)

    else:
        # triple operand form
        a = operand.get(ctx, i, 1)
        b = operand.get(ctx, i, 2)

        if b.size < a.size:
            prev_b = b
            b = ctx.tmp(a.size)
            ctx.emit(  sex_  (prev_b, b))

        result = ctx.tmp(a.size * 2)

        ctx.emit(  mul_  (a, b, result))

        operand.set(ctx, i, 0, result)

        _imul_set_flags(ctx, result)


def x86_inc(ctx, i):
    a = operand.get(ctx, i, 0)

    b = imm(1, a.size)
    result = ctx.tmp(a.size * 2)

    ctx.emit(  add_  (a, b, result))

    _add_set_flags(ctx, a, b, result, cf=False)

    operand.set(ctx, i, 0, result)


def x86_neg(ctx, i):
    a = operand.get(ctx, i, 0)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  sub_  (imm(0, a.size), a, result))

    _sub_set_flags(ctx, imm(0, a.size), a,  result)

    operand.set(ctx, i, 0, result)


def x86_mul(ctx, i):
    b = operand.get(ctx, i, 0)

    a = ctx.tmp(b.size)
    result = ctx.tmp(b.size * 2)

    ctx.emit(  str_  (ctx.accumulator, a))
    ctx.emit(  mul_  (a, b, result))

    if result.size == 16:
        ctx.emit(  str_  (result, ctx.accumulator))
    else:
        high_word = ctx.tmp(result.size // 2)
        low_word = ctx.tmp(result.size // 2)
        ctx.emit(  str_  (result, low_word))
        ctx.emit(  lshr_ (result, imm(result.size // 2, 8), high_word))
        ctx.emit(  str_  (low_word, ctx.accumulator))
        ctx.emit(  str_  (high_word, ctx.data))

    #_mul_set_flags(ctx, result)


def x86_sbb(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  sub_  (a, b, result))
    ctx.emit(  sub_  (result, r('cf', 8), result))

    _sub_set_flags(ctx, a, b, result)

    operand.set(ctx, i, 0, result, clear=True)


def x86_sub(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  sub_  (a, b, result))

    _sub_set_flags(ctx, a, b, result)

    operand.set(ctx, i, 0, result)


def x86_xadd(ctx, i):
    a = operand.get(ctx, i, 0)
    b = operand.get(ctx, i, 1)

    b = _sign_extend(ctx, a, b)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  add_  (a, b, result))

    _add_set_flags(ctx, a, b, result)

    operand.set(ctx, i, 0, result)
    operand.set(ctx, i, 1, a)
