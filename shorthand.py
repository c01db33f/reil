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

"""reil.shorthand

This module contains shorthand functions for creating various REIL
instructions and operands.
"""


import reil.definitions as reil


def imm(value, size):
    """Shorthand function for creating a REIL immediate operand.

    Args:
        value (int): The value of the operand.
        size (int): The size in bits of the operand.
    """

    return reil.ImmediateOperand(value, size)


def off(offset):
    """Shorthand function for creating a REIL offset operand.

    Args:
        offset (int): The value of the operand (relative offset within
    the current native instruction).
    """

    return reil.OffsetOperand(offset)


def r(name, size):
    """Shorthand function for creating a REIL register operand.

    Args:
        name (string): The name of the register.
        size (int): The size in bits of the operand.
    """

    return reil.RegisterOperand(name, size)


def t(index, size):
    """Shorthand function for creating a REIL temporary operand.

    Args:
        index (string): The index of the temporary register.
        size (int): The size in bits of the operand.
    """

    return reil.TemporaryOperand(index, size)


def add_(input0, input1, output):
    """Adds the two values given in the first and second operand and
    writes the result to the third operand. The input operands can be
    literals and register values. The output operand must be a
    register.
    """

    return reil.Instruction(reil.ADD, input0, input1, output)


def and_(input0, input1, output):
    """Binary AND operation that connects the first two operands and
    stores the result in the third operand. The input operands can be
    literals and register values. The output operand must be a register.
    """

    return reil.Instruction(reil.AND, input0, input1, output)


def bisz_(condition, output):
    """Sets a flag depending on whether another value is zero. The
    input operand can be a literal or a register value. The output
    operand is a register.
    """

    return reil.Instruction(reil.BISZ, condition, None, output)


def bsh_(input0, input1, output):
    """Performs a logical shift on a value. If the second operand is
    positive, the shift is a left-shift. If the second operand is
    negative, the shift is a right-shift. The two input operands can
    be either registers or literals while the output operand must be
    a register.
    """

    return reil.Instruction(reil.BSH, input0, input1, output)


def div_(input0, input1, output):
    """Performs an unsigned division on the two input operands. The
    first input operand is the dividend, the second input operand is
    the divisor. The two input operands can be either registers or
    literals while the output operand must be a register.
    """

    return reil.Instruction(reil.DIV, input0, input1, output)


def jcc_(condition, target):
    """Performs a conditional jump to another location if the first
    input operand is not zero. The first input operand can be either
    a register or a literal that specifies the condition. The third
    operand specifies the target address of the jump. It can be
    either a register, a literal, or a REIL offset.
    """

    return reil.Instruction(reil.JCC, condition, None, target)


def ldm_(address, output):
    """Loads a value from memory. The first operand specifies the
    address to read from. It can be either a register or a literal.
    The third operand must be a register where the loaded value is
    stored. The size of the third operand determines how many bytes
    are read from memory.
    """

    return reil.Instruction(reil.LDM, address, None, output)


def mod_(input0, input1, output):
    """Performs a modulo operation on the first two operands. The
    two input operands can be either registers or literals while
    the output operand must be a register.
    """

    return reil.Instruction(reil.MOD, input0, input1, output)


def mul_(input0, input1, output):
    """Performs an unsigned multiplication on the two input operands.
    The two input operands can be either registers or literals while
    the output operand must be a register.
    """

    return reil.Instruction(reil.MUL, input0, input1, output)


def nop_():
    """Does nothing."""

    return reil.Instruction(reil.NOP, None, None, None)


def or_(input0, input1, output):
    """Binary OR operation that connects the first two operands and
    stores the result in the third operand. The input operands can be
    literals and register values. The output operand must be a
    register.
    """

    return reil.Instruction(reil.OR, input0, input1, output)


def stm_(value, address):
    """Stores a value to memory. The first operand is the register
    value or literal to be stored in memory. The third operand is the
    register value or literal that contains the memory address where
    the value is stored. The size of the first operand determines the
    number of bytes to be written to memory.
    """

    return reil.Instruction(reil.STM, value, None, address)


def str_(input0, output):
    """Copies a value to a register. The input operand can be either
    a literal or a register. The output operand must be a register.
    If the output operand is of a larger size than the input operand,
    the input is zero-extended.
    """

    return reil.Instruction(reil.STR, input0, None, output)


def sub_(input0, input1, output):
    """Subtracts the second input operand from the first input operand
    and writes the result to the output operand. The input operands can
    be literals and register values. The output operand must be a
    register.
    """

    return reil.Instruction(reil.SUB, input0, input1, output)


def undef_(register):
    """Flags a register value as undefined. This indicates that in the
    instructions following the UNDEF instruction, no assumption must be
    made about the value of the register until the register is written
    again.
    """

    return reil.Instruction(reil.UNDEF, None, None, register)


def unkn_():
    """Placeholder instruction that is used to translate every native
    instruction that can not be translated by the REIL translator.
    """

    return reil.Instruction(reil.UNKN, None, None, None)


def xor_(input0, input1, output):
    """Binary XOR operation that connects the first two operands and
    stores the result in the third operand. The input operands can be
    literals and register values. The output operand must be a
    register.
    """

    return reil.Instruction(reil.XOR, input0, input1, output)


def bisnz_(condition, output):
    """Extended REIL opcode.

    Sets a flag depending on whether another value is nonzero. The
    input operand can be a literal or a register value. The output
    operand is a register.
    """

    return reil.Instruction(reil.BISNZ, condition, None, output)


def equ_(input0, input1, output):
    """Extended REIL opcode.

    Sets a flag depending on whether another two values are equal. The
    input operands can be literal or register values. The output
    operand is a register.
    """

    return reil.Instruction(reil.EQU, input0, input1, output)


def lshl_(input0, input1, output):
    """Extended REIL opcode.

    Performs a logical left shift on a value. The two input operands can
    be either registers or literals while the output operand must be
    a register.
    """

    return reil.Instruction(reil.LSHL, input0, input1, output)


def lshr_(input0, input1, output):
    """Extended REIL opcode.

    Performs a logical right shift on a value. The two input operands can
    be either registers or literals while the output operand must be
    a register.
    """

    return reil.Instruction(reil.LSHR, input0, input1, output)


def ashr_(input0, input1, output):
    """Extended REIL opcode.

    Performs an arithmetical right shift on a value. The two input
    operands can be either registers or literals while the output operand
    must be a register.
    """

    return reil.Instruction(reil.ASHR, input0, input1, output)


def sdiv_(input0, input1, output):
    """Performs a signed division on the two input operands. The
    first input operand is the dividend, the second input operand is
    the divisor. The two input operands can be either registers or
    literals while the output operand must be a register.
    """

    return reil.Instruction(reil.SDIV, input0, input1, output)


def sex_(input0, output):
    """Extended REIL opcode.

    Performs sign extension on a value. This operand behaves identically
    to the STR opcode, unless the output operand is of a larger size to
    the input operand, in which case the input is sign-extended instead
    of zero-extended.
    """

    return reil.Instruction(reil.SEX, input0, None, output)


def sys_(input0=None):
    """Extended REIL opcode.

    This opcode is used to indicate a transition between user and
    supervisor level code. On platforms where the standard mechanism
    for making this transition contains an inline parameter, for
    example the x86 int instruction, this value will be passed as the
    first input operand.
    """

    return reil.Instruction(reil.SYS, input0, None, None)