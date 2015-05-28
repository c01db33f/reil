# -*- coding: utf-8 -*-

#    Copyright 2015 Mark Brand - c01db33f (at) gmail.com
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

"""reil.x86.ascii - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of the x86 ASCII adjust instructions
used for binary-coded-decimal arithmetic.
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


def x86_aaa(ctx, i):

    al = operand.get_register(ctx, i, 'al')
    ah = operand.get_register(ctx, i, 'ah')

    result_al = ctx.tmp(8)
    result_ah = ctx.tmp(8)
    tmp0 = ctx.tmp(16)
    tmp1 = ctx.tmp(8)

    # ((al & 0xf) > 9
    ctx.emit(  and_  (al, imm(0xf, 8), result_al))
    ctx.emit(  sub_  (result_al, imm(9, 8), tmp0))
    ctx.emit(  and_  (tmp0, imm(0xff00, 16), tmp0))
    ctx.emit(  bisnz_(tmp0, tmp1))
    #                  || af == 1)
    ctx.emit(  or_   (tmp1, r('af', 8), tmp1))
    ctx.emit(  jcc_  (tmp1, 'adjust'))

    ctx.emit(  str_  (imm(0, 8), r('af', 8)))
    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('adjust')
    ctx.emit(  add_  (result_al, imm(6, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_al))

    ctx.emit(  add_  (ah, imm(1, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_ah))

    ctx.emit(  str_  (imm(1, 8), r('af', 8)))
    ctx.emit(  str_  (imm(1, 8), r('cf', 8)))

    ctx.emit('done')

    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('zf', 8)))
    ctx.emit(  undef_(r('pf', 8)))

    operand.set_register(ctx, i, 'al', result_al)
    operand.set_register(ctx, i, 'ah', result_ah)


def x86_aad(ctx, i):

    al = operand.get_register(ctx, i, 'al')
    ah = operand.get_register(ctx, i, 'ah')
    base = imm(10, 8)

    result_al = ctx.tmp(8)
    tmp0 = ctx.tmp(16)

    ctx.emit(  mul_  (ah, base, tmp0))
    ctx.emit(  add_  (al, tmp0, tmp0))
    ctx.emit(  str_  (tmp0, result_al))

    set_sf(ctx, result_al)
    set_zf(ctx, result_al)
    set_pf(ctx, result_al)

    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('af', 8)))
    ctx.emit(  undef_(r('cf', 8)))

    operand.set_register(ctx, i, 'al', result_al)


def x86_aam(ctx, i):

    al = operand.get_register(ctx, i, 'al')
    ah = operand.get_register(ctx, i, 'ah')
    base = imm(10, 8)

    result_al = ctx.tmp(8)
    result_ah = imm(0, 8)
    tmp0 = ctx.tmp(16)

    ctx.emit(  div_  (al, base, result_ah))
    ctx.emit(  mod_  (al, tmp0, result_al))

    set_sf(ctx, result_al)
    set_zf(ctx, result_al)
    set_pf(ctx, result_al)

    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('af', 8)))
    ctx.emit(  undef_(r('cf', 8)))

    operand.set_register(ctx, i, 'al', result_al)
    operand.set_register(ctx, i, 'ah', result_ah)


def x86_aas(ctx, i):

    al = operand.get_register(ctx, i, 'al')
    ah = operand.get_register(ctx, i, 'ah')

    result_al = ctx.tmp(8)
    result_ah = ctx.tmp(8)
    tmp0 = ctx.tmp(16)
    tmp1 = ctx.tmp(8)

    # ((al & 0xf) > 9
    ctx.emit(  and_  (al, imm(0xf, 8), result_al))
    ctx.emit(  sub_  (result_al, imm(9, 8), tmp0))
    ctx.emit(  and_  (tmp0, imm(0xff00, 16), tmp0))
    ctx.emit(  bisnz_(tmp0, tmp1))
    #                  || af == 1)
    ctx.emit(  or_   (tmp1, r('af', 8), tmp1))
    ctx.emit(  jcc_  (tmp1, 'adjust'))

    ctx.emit(  str_  (imm(0, 8), r('af', 8)))
    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done'))

    ctx.emit('adjust')
    ctx.emit(  sub_  (result_al, imm(6, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_al))

    ctx.emit(  sub_  (ah, imm(1, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_ah))

    ctx.emit(  str_  (imm(1, 8), r('af', 8)))
    ctx.emit(  str_  (imm(1, 8), r('cf', 8)))

    ctx.emit('done')

    ctx.emit(  undef_(r('of', 8)))
    ctx.emit(  undef_(r('sf', 8)))
    ctx.emit(  undef_(r('zf', 8)))
    ctx.emit(  undef_(r('pf', 8)))

    operand.set_register(ctx, i, 'al', result_al)
    operand.set_register(ctx, i, 'ah', result_ah)


def x86_daa(ctx, i):

    al = operand.get_register(ctx, i, 'al')

    result_al = ctx.tmp(8)
    tmp0 = ctx.tmp(16)
    tmp1 = ctx.tmp(8)

    # ((al & 0xf) > 9
    ctx.emit(  and_  (al, imm(0xf, 8), result_al))
    ctx.emit(  sub_  (result_al, imm(9, 8), tmp0))
    ctx.emit(  and_  (tmp0, imm(0xff00, 16), tmp0))
    ctx.emit(  bisnz_(tmp0, tmp1))
    #                  || af == 1)
    ctx.emit(  or_   (tmp1, r('af', 8), tmp1))
    ctx.emit(  jcc_  (tmp1, 'adjust0'))

    ctx.emit(  str_  (imm(0, 8), r('af', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done0'))

    ctx.emit('adjust0')
    ctx.emit(  add_  (result_al, imm(6, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_al))
    ctx.emit(  str_  (imm(1, 8), r('af', 8)))

    ctx.emit('done0')

    # al > 0x99
    ctx.emit(  sub_  (al, imm(0x99, 8), tmp0))
    ctx.emit(  and_  (tmp0, imm(0xff00, 16), tmp0))
    ctx.emit(  bisnz_(tmp0, tmp1))
    #           || cf == 1
    ctx.emit(  or_   (tmp1, r('cf', 8), tmp1))
    ctx.emit(  jcc_  (tmp1, 'adjust1'))

    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done1'))

    ctx.emit('adjust1')
    ctx.emit(  add_  (result_al, imm(0x60, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_al))
    ctx.emit(  str_  (imm(1, 8), r('cf', 8)))

    ctx.emit('done1')

    set_sf(ctx, result_al)
    set_zf(ctx, result_al)
    set_pf(ctx, result_al)

    ctx.emit(  undef_(r('of', 8)))

    operand.set_register(ctx, i, 'al', result_al)


def x86_das(ctx, i):

    al = operand.get_register(ctx, i, 'al')

    result_al = ctx.tmp(8)
    tmp0 = ctx.tmp(16)
    tmp1 = ctx.tmp(8)

    # ((al & 0xf) > 9
    ctx.emit(  and_  (al, imm(0xf, 8), result_al))
    ctx.emit(  sub_  (result_al, imm(9, 8), tmp0))
    ctx.emit(  and_  (tmp0, imm(0xff00, 16), tmp0))
    ctx.emit(  bisnz_(tmp0, tmp1))
    #                  || af == 1)
    ctx.emit(  or_   (tmp1, r('af', 8), tmp1))
    ctx.emit(  jcc_  (tmp1, 'adjust0'))

    ctx.emit(  str_  (imm(0, 8), r('af', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done0'))

    ctx.emit('adjust0')
    ctx.emit(  sub_  (result_al, imm(6, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_al))
    ctx.emit(  str_  (imm(1, 8), r('af', 8)))

    ctx.emit('done0')

    # al > 0x99
    ctx.emit(  sub_  (al, imm(0x99, 8), tmp0))
    ctx.emit(  and_  (tmp0, imm(0xff00, 16), tmp0))
    ctx.emit(  bisnz_(tmp0, tmp1))
    #           || cf == 1
    ctx.emit(  or_   (tmp1, r('cf', 8), tmp1))
    ctx.emit(  jcc_  (tmp1, 'adjust1'))

    ctx.emit(  str_  (imm(0, 8), r('cf', 8)))
    ctx.emit(  jcc_  (imm(1, 8), 'done1'))

    ctx.emit('adjust1')
    ctx.emit(  sub_  (result_al, imm(0x60, 8), tmp0))
    ctx.emit(  str_  (tmp0, result_al))
    ctx.emit(  str_  (imm(1, 8), r('cf', 8)))

    ctx.emit('done1')

    set_sf(ctx, result_al)
    set_zf(ctx, result_al)
    set_pf(ctx, result_al)

    ctx.emit(  undef_(r('of', 8)))

    operand.set_register(ctx, i, 'al', result_al)