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

"""reil.native

This module contains the basic definitions for the native instructions
produced by this library.

.. REIL language specification:
    http://www.zynamics.com/binnavi/manual/html/reil_language.htm
"""

class Instruction(object):

    __slots__ = ['address', 'mnemonic', 'il_instructions', 'ends_basic_block', 'size']

    def __init__(self, address, mnemonic, il_instructions, ends_basic_block=False, size=0):
        self.address = address
        self.mnemonic = mnemonic
        self.il_instructions = il_instructions
        self.ends_basic_block = ends_basic_block
        self.size = size

    def __str__(self):
        return '{:08x} {:1} {}'.format(self.address, self.ends_basic_block, self.mnemonic)