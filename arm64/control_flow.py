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

"""reil.arm64.control_flow - ARMv8 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv8 machine code.

This file is responsible for translation of basic control flow instructions
such as b, bl.
"""

import reil.error
from reil import *
from reil.shorthand import *
from reil.utilities import *

import reil.arm64.conditional as conditional
import reil.arm64.operand as operand

def arm64_b(ctx, i):
    a = operand.get(ctx, i, 0)
    cond = conditional.condition(ctx, i.cc)
    ctx.emit(  jcc_  (cond, a))
