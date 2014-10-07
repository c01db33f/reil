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

"""reil.definitions

This module contains the basic definitions for the REIL instructions
that are used by this library.

.. REIL language specification:
    http://www.zynamics.com/binnavi/manual/html/reil_language.htm
"""

ADD   = 0
"""Adds the two values given in the first and second operand and
writes the result to the third operand. The input operands can be
literals and register values. The output operand must be a
register.
"""

AND   = 1
"""Binary AND operation that connects the first two operands and
stores the result in the third operand. The input operands can be
literals and register values. The output operand must be a register.
"""

BISZ  = 2
"""Sets a flag depending on whether another value is zero. The
input operand can be a literal or a register value. The output
operand is a register.
"""

BSH   = 3
"""Performs a logical shift on a value. If the second operand is
positive, the shift is a left-shift. If the second operand is
negative, the shift is a right-shift. The two input operands can
be either registers or literals while the output operand must be
a register.
"""

DIV   = 4
"""Performs an unsigned division on the two input operands. The
first input operand is the dividend, the second input operand is
the divisor. The two input operands can be either registers or
literals while the output operand must be a register.
"""

JCC   = 5
"""Performs a conditional jump to another location if the first
input operand is not zero. The first input operand can be either
a register or a literal that specifies the condition. The third
operand specifies the target address of the jump. It can be
either a register, a literal, or a REIL offset.
"""

LDM   = 6
"""Loads a value from memory. The first operand specifies the
address to read from. It can be either a register or a literal.
The third operand must be a register where the loaded value is
stored. The size of the third operand determines how many bytes
are read from memory.
"""

MOD   = 7
"""Performs a modulo operation on the first two operands. The
two input operands can be either registers or literals while
the output operand must be a register.
"""

MUL   = 8
"""Performs an unsigned multiplication on the two input operands.
The two input operands can be either registers or literals while
the output operand must be a register.
"""

NOP   = 9
"""Does nothing."""

OR    = 10
"""Binary OR operation that connects the first two operands and
stores the result in the third operand. The input operands can be
literals and register values. The output operand must be a
register.
"""

STM   = 11
"""Stores a value to memory. The first operand is the register
value or literal to be stored in memory. The third operand is the
register value or literal that contains the memory address where
the value is stored. The size of the first operand determines the
number of bytes to be written to memory.
"""

STR   = 12
"""Copies a value to a register. The input operand can be either
a literal or a register. The output operand must be a register.
If the output operand is of a larger size than the input operand,
the input is zero-extended.
"""

SUB   = 13
"""Subtracts the second input operand from the first input operand
and writes the result to the output operand. The input operands can
be literals and register values. The output operand must be a
register.
"""

UNDEF = 14
"""Flags a register value as undefined. This indicates that in the
instructions following the UNDEF instruction, no assumption must be
made about the value of the register until the register is written
again.
"""

UNKN  = 15
"""Placeholder instruction that is used to translate every native
instruction that can not be translated by the REIL translator.
"""

XOR   = 16
"""Binary XOR operation that connects the first two operands and
stores the result in the third operand. The input operands can be
literals and register values. The output operand must be a
register.
"""

BISNZ = 17
"""Extended REIL opcode.

Sets a flag depending on whether another value is nonzero. The
input operand can be a literal or a register value. The output
operand is a register.
"""

EQU   = 18
"""Extended REIL opcode.

Sets a flag depending on whether another two values are equal. The
input operands can be literal or register values. The output
operand is a register.
"""

LSHL  = 19
"""Extended REIL opcode.

Performs a logical left shift on a value. The two input operands can
be either registers or literals while the output operand must be
a register.
"""

LSHR  = 20
"""Extended REIL opcode.

Performs a logical right shift on a value. The two input operands can
be either registers or literals while the output operand must be
a register.
"""

ASHR  = 21
"""Extended REIL opcode.

Performs an arithmetical right shift on a value. The two input
operands can be either registers or literals while the output operand
must be a register.
"""

SDIV  = 22
"""Performs a signed division on the two input operands. The
first input operand is the dividend, the second input operand is
the divisor. The two input operands can be either registers or
literals while the output operand must be a register.
"""

SEX   = 23
"""Extended REIL opcode.

Performs sign extension on a value. This operand behaves identically
to the STR opcode, unless the output operand is of a larger size to
the input operand, in which case the input is sign-extended instead
of zero-extended.
"""

SYS   = 24
"""Extended REIL opcode.

This opcode is used to indicate a transition between user and
supervisor level code. On platforms where the standard mechanism
for making this transition contains an inline parameter, for
example the x86 int instruction, this value will be passed as the
first input operand.
"""

_opcode_string_map = [
    'add',
    'and',
    'bisz',
    'bsh',
    'div',
    'jcc',
    'ldm',
    'mod',
    'mul',
    'nop',
    'or',
    'stm',
    'str',
    'sub',
    'undef',
    'unkn',
    'xor',
    'bisnz',
    'equ',
    'lshl',
    'lshr',
    'ashr',
    'sdiv',
    'sex',
    'sys',
]


def _opcode_to_string(opcode):
    """Return the printable name for a REIL opcode.

    Args:
        opcode (reil.Opcode): The opcode to provide in printable form.

    Returns:
        A string representing the opcode.
    """

    return _opcode_string_map[opcode]


class ImmediateOperand(object):
    """Class for REIL immediate operands.

    Args:
        value (int): The value of the operand.
        size (int): The size in bits of the operand.

    Attributes:
        value (int): The value of the operand.
        size (int): The size in bits of the operand.
    """

    __slots__ = ('value', 'size')


    def __init__(self, value, size):
        self.value = value
        self.size = size


    def __str__(self):
        return '({}, {})'.format(self.value, self.size)


class OffsetOperand(object):
    """Class for REIL offset operands.

    Args:
        offset (int): The value of the operand (relative offset within
    the current native instruction).

    Attributes:
        offset (int): The value of the operand (relative offset within
    the current native instruction).
    """

    __slots__ = ('offset', 'size')


    def __init__(self, offset):
        self.offset = offset
        self.size = 8


    def __str__(self):
        return '(.{:02x}, {})'.format(self.offset, self.size)


class RegisterOperand(object):
    """Class for REIL native register operands.

    Args:
        name (string): The name of the register.
        size (int): The size in bits of the operand.

    Attributes:
        name (string): The name of the register.
        size (int): The size in bits of the operand.
    """

    __slots__ = ('name', 'size')


    def __init__(self, name, size):
        self.name = name
        self.size = size


    def __str__(self):
        return '({}, {})'.format(self.name, self.size)


class TemporaryOperand(RegisterOperand):
    """Class for REIL temporary register operands.

    Args:
        index (int): The index of the temporary register.
        size (int): The size in bits of the operand.

    Attributes:
        index (int): The index of the temporary register.
        size (int): The size in bits of the operand.
    """

    __slots__ = ('name', 'size')


    def __init__(self, index, size):
        self.name = 't{:02}'.format(index)
        self.size = size


class Instruction(object):
    """Object representing a single REIL instruction.

    Args:
        opcode (reil.Opcode): The opcode for this instruction.
        input0 (reil.Operand, optional): The first input operand.
        input1 (reil.Operand, optional): The second input operand.
        output (reil.Operand, optional): The output operand.

    Attributes:
        opcode (reil.Opcode): The opcode for this instruction.
        input0 (reil.Operand): The first input operand.
        input1 (reil.Operand): The second input operand.
        output (reil.Operand): The output operand.
    """

    __slots__ = ('opcode', 'input0', 'input1', 'output')


    def __init__(self, opcode, input0=None, input1=None, output=None):
        self.opcode = opcode
        self.input0 = input0
        self.input1 = input1
        self.output = output


    def __str__(self):
        output = _opcode_to_string(self.opcode)
        if self.input0 is not None:
            output += ' {}'.format(self.input0)
        if self.input1 is not None:
            output += ', {}'.format(self.input1)
        if self.output is not None:
            output += ', {}'.format(self.output)
        return output
