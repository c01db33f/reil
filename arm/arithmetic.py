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

"""reil.arm.arithmetic - ARMv7 and Thumbv2 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv7 and Thumbv2 machine code.

This file is responsible for translation of basic arithmetic instructions
such as add, mul, div
"""

import reil.error
from reil import *
from reil.shorthand import *
from reil.utilities import *

import reil.arm.operand as operand

def arm_add(ctx, i):
    if len(i.operands) == 3:
        dst_idx = 0
        a_idx = 1
        b_idx = 2
    else:
        dst_idx = 0
        a_idx = 0
        b_idx = 1

    a = operand.get(ctx, i, a_idx)
    b = operand.get(ctx, i, b_idx)

    result = ctx.tmp(a.size * 2)

    ctx.emit(  add_  (a, b, result))

    if i.update_flags:
        raise NotImplementedError()

    operand.set(ctx, i, dst_idx, result)

