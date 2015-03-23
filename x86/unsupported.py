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

"""reil.x86.unsupported - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation stubs for classes of instructions that
are not supported by the translator
"""

import capstone
import capstone.x86

import reil
import reil.error
from reil.shorthand import *

import reil.x86.conditional as conditional
import reil.x86.operand as operand
from reil.x86.utilities import *


def complicated(ctx, i):
    """Instruction not implemented, because it's complicated :-P."""
    ctx.emit(  unkn_())


def floating_point(ctx, i):
    """Instruction not implemented; REIL has no floating-point support."""
    ctx.emit(  unkn_())


def low_level(ctx, i):
    """Instruction not implemented; it's effects are too low-level."""
    ctx.emit(  unkn_())


def privileged(ctx, i):
    """Instruction not implemented; it requires CPL0."""
    ctx.emit(  unkn_())


def requires_exceptions(ctx, i):
    """Instruction not implemented; it requires processor exceptions to be useful."""
    ctx.emit(  unkn_())