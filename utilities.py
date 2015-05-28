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

"""reil.utilities

This module contains a couple of helper functions used in more than one
translator module.
"""

def carry_bit(size):
    """The mask required for the carry bit on a computation with a
    result of bit-size 'size'.
    """

    return 1 << size


def sign_bit(size):
    """The mask required for the sign bit of a value with bit-size
    'size'.
    """

    return 1 << (size - 1)


def mask(size):
    """The basic bitmask to extract the value of bit-size 'size'."""

    if size == 8:
        return 0xff
    elif size == 16:
        return 0xffff
    elif size == 32:
        return 0xffffffff
    elif size == 64:
        return 0xffffffffffffffff
    elif size == 128:
        return 0xffffffffffffffffffffffffffffffff