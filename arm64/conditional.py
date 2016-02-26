# -*- coding: utf-8 -*-

#    Copyright 2016 Mark Brand - c01db33f (at) gmail.com
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

"""reil.arm64.conditional - ARMv8 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv8 machine code.

This file contains helpers for conditional instructions
"""

from reil.shorthand import *
from reil.utilities import *

A  = 0
EQ = 1
NE = 2
HS = 3
LO = 4
MI = 5
PL = 6
VS = 7
VC = 8
HI = 9
LS = 10
GE = 11
LT = 12
GT = 13
LE = 14
AL = 15
NV = 16

def condition(ctx, cc):
    # we implement as per the architecture reference manual
    # TODO: optimise instead.
    cb = (cc >> 1) & 0b111
    
    if cb == 0b111:
        cond = imm(1, 8)
    else:
        cond = ctx.tmp(8)

    # evaluate base condition
    if cb == 0b000:
        ctx.emit(  bisnz_ (r('z', 8), cond))
    elif cb == 0b001:
        ctx.emit(  bisnz_ (r('c', 8), cond))
    elif cb == 0b010:
        ctx.emit(  bisnz_ (r('n', 8), cond))
    elif cb == 0b011:
        ctx.emit(  bisnz_ (r('v', 8), cond))
    elif cb == 0b100:
        t0 = ctx.tmp(8)
        t1 = ctx.tmp(8)
        ctx.emit(  bisnz_ (r('c', 8), t0))
        ctx.emit(  bisz_  (r('z', 8), t1))
        ctx.emit(  and_   (t0, t1, cond))
    elif cb == 0b101:
        ctx.emit(  equ_   (r('n', 8), r('v', 8), cond))
    elif cb == 0b110:
        t0 = ctx.tmp(8)
        t1 = ctx.tmp(8)
        ctx.emit(  equ_   (r('n', 8), r('v', 8), t0))
        ctx.emit(  bisz_  (r('z', 8), t1))
        ctx.emit(  and_   (t0, t1, cond))

    if cc != 0b1111 and cc & 0b1 == 1:
        ctx.emit(  bisz_  (cond, cond))

    return cond
