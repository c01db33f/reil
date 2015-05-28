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

"""reil.arm.utilities - ARMv7 and Thumbv2 translation utility functions.

This module contains all the silly little utility functions that didn't
belong anywhere else.
"""

import reil.definitions as reil
from reil.shorthand import *
from reil.utilities import *


def set_N(ctx, result):
    """compute N(egative) flag based on size of input result"""
    ctx.emit(  and_  (result, imm(sign_bit(result.size), result.size), r('N', 8)))


def set_Z(ctx, result):
    """compute zero flag"""
    ctx.emit(  bisz_ (result, r('Z', 8)))