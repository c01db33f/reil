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

"""reil.x86.conditional - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file contains helpers for x86 conditional instructions
"""

from reil.shorthand import *
from reil.utilities import *

A    = 0
AE   = 1
B    = 2
BE   = 3
CXZ  = 4
ECXZ = 5
RCXZ = 6
E    = 7
G    = 8
GE   = 9
L    = 10
LE   = 11
UN   = 12
NE   = 13
NO   = 14
NP   = 15
NS   = 16
O    = 17
P    = 18
S    = 19

def condition(ctx, cc):

    # default to unconditional
    cond = imm(1, 8)

    if cc != UN:
        # conditional
        cond = ctx.tmp(8)

        if cc == A:
            # above (CF == 0 && ZF == 0)
            tmp0 = ctx.tmp(8)
            ctx.emit(  or_    (r('cf', 8), r('zf', 8), tmp0))
            ctx.emit(  bisz_  (tmp0, cond))

        elif cc == AE:
            # above or equal (CF == 0)
            ctx.emit(  bisz_  (r('cf', 8), cond))

        elif cc == B:
            # below (CF == 1)
            ctx.emit(  bisnz_ (r('cf', 8), cond))

        elif cc == BE:
            # below or equal (CF == 1 || ZF == 1)
            ctx.emit(  or_    (r('cf', 8), r('zf', 8), cond))

        elif cc == CXZ:
            # if cx is zero (cx == 0)
            ctx.emit(  bisz_  (r('cx', 16), cond))

        elif cc == ECXZ:
            # if ecx is zero (ecx == 0)
            ctx.emit(  bisz_  (r('ecx', 32), cond))

        elif cc == RCXZ:
            # if rcx is zero (rcx == 0)
            ctx.emit(  bisz_  (r('rcx', 64), cond))

        elif cc == E:
            # equal (ZF == 1)
            ctx.emit(  bisnz_ (r('zf', 8), cond))

        elif cc == G:
            # greater (ZF == 0 && SF == OF)
            tmp0 = ctx.tmp(8)
            tmp1 = ctx.tmp(8)
            ctx.emit(  equ_   (r('sf', 8), r('of', 8), tmp0))
            ctx.emit(  bisz_  (r('zf', 8), tmp1))
            ctx.emit(  and_   (tmp0, tmp1, cond))

        elif cc == GE:
            # greater or equal (SF == OF)
            ctx.emit(  equ_   (r('sf', 8), r('of', 8), cond))

        elif cc == L:
            # less (SF != OF)
            tmp0 = ctx.tmp(8)
            ctx.emit(  equ_   (r('sf', 8), r('of', 8), tmp0))
            ctx.emit(  bisz_  (tmp0, cond))

        elif cc == LE:
            # less or equal (ZF == 1 || SF != OF)
            tmp0 = ctx.tmp(8)
            tmp1 = ctx.tmp(8)
            ctx.emit(  equ_   (r('sf', 8), r('of', 8), tmp0))
            ctx.emit(  bisz_  (tmp0, tmp1))
            ctx.emit(  or_    (r('zf', 8), tmp1, cond))

        elif cc == NE:
            # not equal (ZF == 0)
            ctx.emit(  bisz_  (r('zf', 8), cond))

        elif cc == NO:
            # not overflow (OF == 0)
            ctx.emit(  bisz_  (r('of', 8), cond))

        elif cc == NP:
            # not parity (PF == 0)
            ctx.emit(  bisz_  (r('pf', 8), cond))

        elif cc == NS:
            # not sign (SF == 0)
            ctx.emit(  bisz_  (r('sf', 8), cond))

        elif cc == O:
            # overflow (OF == 1)
            ctx.emit(  bisnz_ (r('of', 8), cond))

        elif cc == P:
            # parity (PF == 1)
            ctx.emit(  bisnz_ (r('pf', 8), cond))

        elif cc == S:
            # sign (SF == 1)
            ctx.emit(  bisnz_ (r('sf', 8), cond))

    return cond