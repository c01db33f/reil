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

"""reil.arm.control_flow - ARMv7 and Thumbv2 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv7 and Thumbv2 machine code.

This file is responsible for translation of control flow instructions
such as b, blx
"""

import reil.error
from reil import *
from reil.shorthand import *
from reil.utilities import *

import reil.arm.operand as operand


def arm_b(ctx, i):
    target = operand.get(ctx, i, 0)
    ctx.emit(  jcc_  (imm(1, 8), target))


def arm_blx(ctx, i):
    target = operand.get(ctx, i, 0)

    pc = operand.get_register(ctx, i, 'pc')
    if ctx.thumb:
        prev_pc = pc
        pc = ctx.tmp(32)
        ctx.emit(  or_   (prev_pc, imm(1, 32), pc))

    operand.set_register(ctx, i, 'lr', pc)
    ctx.emit(  jcc_  (imm(1, 8), target))
