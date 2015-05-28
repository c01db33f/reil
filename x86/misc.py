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
from reil.utilities import *

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


def x86_arpl(ctx, i):

    dest_seg = operand.get(ctx, i, 0)
    src_seg = operand.get(ctx, i, 1)

    dest_rpl = ctx.tmp(16)
    src_rpl = ctx.tmp(16)
    tmp0 = ctx.tmp(32)
    tmp1 = ctx.tmp(8)
    result_seg = ctx.tmp(16)
    tmp2 = ctx.tmp(16)

    ctx.emit(  lshr_ (dest_seg, imm(14, 8), dest_rpl))
    ctx.emit(  lshr_ (src_seg, imm(14, 8), src_rpl))

    ctx.emit(  sub_  (dest_seg, src_seg, tmp0))
    ctx.emit(  and_  (tmp0, imm(sign_bit(32), 32), tmp0))
    ctx.emit(  bisz_ (tmp0, tmp1))
    ctx.emit(  jcc_  ('check_passed'))
    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))
    ctx.emit(  and_  (dest_seg, imm(0b0011111111111111, 16), result_seg))
    ctx.emit(  and_  (src_seg, imm(0b1100000000000000, 16), tmp2))
    ctx.emit(  or_   (dest_seg, tmp2, dest_seg))

    operand.set(ctx, i, 0, result_seg)

    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('check_passed')
    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))

    ctx.emit('done')
    ctx.emit(  nop_())


def x86_bswap(ctx, i):
    a = operand.get(ctx, i, 0)

    bytes = unpack(ctx, a, 8)
    bytes.reverse()
    value = pack(ctx, bytes)

    operand.set(ctx, i, 0, value)


def x86_clc(ctx, i):
    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))


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


def x86_cmc(ctx, i):
    ctx.emit(  xor_  (r('cf', 8), imm(1, 8), r('cf', 8)))


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


def x86_cmpxchg8b(ctx, i):
    edx = operand.get_register(ctx, i, 'edx')
    eax = operand.get_register(ctx, i, 'eax')
    edx_eax = ctx.tmp(64)

    ecx = operand.get_register(ctx, i, 'ecx')
    ebx = operand.get_register(ctx, i, 'ebx')
    ecx_ebx = ctx.tmp(64)

    value = operand.get(ctx, i, 0)

    tmp0 = ctx.tmp(64)
    tmp1 = ctx.tmp(8)

    result_eax = ctx.tmp(32)
    result_edx = ctx.tmp(32)

    ctx.emit(  lshl_  (edx, imm(32, 8), edx_eax))
    ctx.emit(  str_   (eax, tmp0))
    ctx.emit(  or_    (edx_eax, tmp0, edx_eax))

    ctx.emit(  equ_  (value, edx_eax, tmp1))
    ctx.emit(  jcc_  (tmp1, 'equal'))

    ctx.emit('not-equal')
    ctx.emit(  str_  (value, result_eax))
    ctx.emit(  lshr_ (value, imm(32, 8), value))
    ctx.emit(  str_  (value, result_edx))

    operand.set_register(ctx, i, 'edx', result_edx)
    operand.set_register(ctx, i, 'eax', result_eax)

    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('equal')
    ctx.emit(  lshl_  (ecx, imm(32, 8), ecx_ebx))
    ctx.emit(  str_   (ebx, tmp0))
    ctx.emit(  or_    (ecx_ebx, tmp0, ecx_ebx))

    operand.set(ctx, i, 0, ecx_ebx)

    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))

    ctx.emit('done')
    ctx.emit(  nop_())


def x86_cmpxchg16b(ctx, i):
    rdx = operand.get_register(ctx, i, 'rdx')
    rax = operand.get_register(ctx, i, 'rax')
    rdx_rax = ctx.tmp(128)

    rcx = operand.get_register(ctx, i, 'rcx')
    rbx = operand.get_register(ctx, i, 'rbx')
    rcx_rbx = ctx.tmp(128)

    value = operand.get(ctx, i, 0)

    tmp0 = ctx.tmp(128)
    tmp1 = ctx.tmp(8)

    result_rax = ctx.tmp(64)
    result_rdx = ctx.tmp(64)

    ctx.emit(  lshl_  (rdx, imm(64, 8), rdx_rax))
    ctx.emit(  str_   (rax, tmp0))
    ctx.emit(  or_    (rdx_rax, tmp0, rdx_rax))

    ctx.emit(  equ_  (value, rdx_rax, tmp1))
    ctx.emit(  jcc_  (tmp1, 'equal'))

    ctx.emit('not-equal')
    ctx.emit(  str_  (value, result_rax))
    ctx.emit(  lshr_ (value, imm(64, 8), value))
    ctx.emit(  str_  (value, result_rdx))

    operand.set_register(ctx, i, 'rdx', result_rdx)
    operand.set_register(ctx, i, 'rax', result_rax)

    ctx.emit(  str_  (imm(0, 8), r('zf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('equal')
    ctx.emit(  lshl_  (rcx, imm(64, 8), rcx_rbx))
    ctx.emit(  str_   (rbx, tmp0))
    ctx.emit(  or_    (rcx_rbx, tmp0, rcx_rbx))

    operand.set(ctx, i, 0, rcx_rbx)

    ctx.emit(  str_  (imm(1, 8), r('zf', 8)))

    ctx.emit('done')
    ctx.emit(  nop_())


def x86_cpuid(ctx, i):
    eax = operand.get_register(ctx, i, 'eax')

    flag = ctx.tmp(8)
    ctx.emit(  equ_  (eax, imm(0, 32), flag))
    ctx.emit(  jcc_  (flag, 'cpuid_basic'))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('cpuid_basic')
    operand.set_register(ctx, i, 'eax', imm(0, 32))
    operand.set_register(ctx, i, 'ebx', imm(0x756e6547, 32))
    operand.set_register(ctx, i, 'ecx', imm(0x49656e69, 32))
    operand.set_register(ctx, i, 'edx', imm(0x6c65746e, 32))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('done')
    ctx.emit(  nop_())


def x86_int(ctx, i):
    ctx.emit(  sys_  (imm(0, 8)))


def x86_int1(ctx, i):
    ctx.emit(  sys_  (imm(1, 8)))


def x86_int3(ctx, i):
    ctx.emit(  sys_  (imm(3, 8)))


def x86_into(ctx, i):
    ctx.emit(  jcc_  (r('of', 8), 'do_interrupt'))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('do_interrupt')
    ctx.emit(  sys_  (imm(4, 8)))

    ctx.emit('done')
    ctx.emit(  nop_  ())


def x86_lahf(ctx, i):
    result_ah = ctx.tmp(8)

    ctx.emit(  str_  (imm(0, 8), result_ah))
    ctx.emit(  or_   (r('sf', 8), result_ah))
    ctx.emit(  lshl_ (result_ah, imm(1, 8), result_ah))
    ctx.emit(  or_   (r('zf', 8), result_ah))
    ctx.emit(  lshl_ (result_ah, imm(2, 8), result_ah))
    ctx.emit(  or_   (r('af', 8), result_ah))
    ctx.emit(  lshl_ (result_ah, imm(2, 8), result_ah))
    ctx.emit(  or_   (r('pf', 8), result_ah))
    ctx.emit(  lshl_ (result_ah, imm(1, 8), result_ah))
    ctx.emit(  or_   (imm(1, 8), result_ah))
    ctx.emit(  lshl_ (result_ah, imm(1, 8), result_ah))
    ctx.emit(  or_   (r('cf', 8), result_ah))

    operand.set_register(ctx, i, 'ah', result_ah)


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