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

"""reil.arm.conditional - ARMv7 and Thumbv2 translators

This module generates REIL (reverse engineering intermediate language)
IL from ARMv7 and Thumbv2 machine code.

This file contains helpers for conditional instructions
"""

from reil.shorthand import *
from reil.utilities import *

def execute(ctx, i):
    print dir(i)