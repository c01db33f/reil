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

"""reil.arm64.translator - ARM64 translator

This module generates REIL (reverse engineering intermediate language)
IL from ARMv8 machine code.
"""


import capstone

import reil.native as native
from reil.shorthand import *

import reil.arm64.arithmetic as arithmetic
import reil.arm64.control_flow as control_flow
import reil.arm64.memory as memory

opcode_handlers = {
  capstone.arm64.ARM64_INS_B:    control_flow.arm64_b,

  capstone.arm64.ARM64_INS_CMP:  arithmetic.arm64_sub,

  capstone.arm64.ARM64_INS_MOV:  memory.arm64_mov,

  capstone.arm64.ARM64_INS_STP:  memory.arm64_stp,
  capstone.arm64.ARM64_INS_STR:  memory.arm64_mov,
}

def process_labels(ris):
    labels = dict()
    i = 0

    # we are modifying ris, hence the nasty loop
    while i < len(ris):
        ri = ris[i]
        if isinstance(ri, str):
            # this is a label, remove
            labels[ri] = i
            ris = ris[:i] + ris[i+1:]
        else:
            i += 1

    for ri in ris:
        if isinstance(ri.output, str):
            # this is a label, replace with offset
            ri.output = off(labels[ri.output])

    return ris


class TranslationContext(object):

    def __init__(self):
        self.temporary_index = 0
        self.reil_instructions = []


    def tmp(self, size):
        output = t(self.temporary_index, size)
        self.temporary_index += 1
        return output


    def emit(self, instruction):
        self.reil_instructions.append(instruction)


    def finalise(self):
        ris = self.reil_instructions

        # reset the context ready for the next instruction
        self.temporary_index = 0
        self.reil_instructions = []

        return process_labels(ris)


def print_instruction(i):
    print('{:x}: {}  {}'.format(i.address, i.mnemonic, i.op_str))


def unknown_opcode(ctx, i):
    print_instruction(i)
    print(i.id)
    raise NotImplementedError()

    ctx.emit(  unkn_())


def _translate(ctx, i):
    if i.id in opcode_handlers:
        opcode_handlers[i.id](ctx, i)
    else:
        print_instruction(i)
        unknown_opcode(ctx, i)

    return ctx.finalise()


def ends_basic_block(i):
    other_flow_control = {
        capstone.arm.ARM_INS_B,
        capstone.arm.ARM_INS_BLX,
    }
    if capstone.arm.ARM_GRP_JUMP in i.groups:
        return True
    elif i.id in other_flow_control:
        return True
    return False


class Arm64TranslationContext(TranslationContext):

    def __init__(self):
        TranslationContext.__init__(self)

        self.registers = {
            capstone.arm64.ARM64_REG_X0:  r('x0',  64),
            capstone.arm64.ARM64_REG_X1:  r('x1',  64),
            capstone.arm64.ARM64_REG_X2:  r('x2',  64),
            capstone.arm64.ARM64_REG_X3:  r('x3',  64),
            capstone.arm64.ARM64_REG_X4:  r('x4',  64),
            capstone.arm64.ARM64_REG_X5:  r('x5',  64),
            capstone.arm64.ARM64_REG_X6:  r('x6',  64),
            capstone.arm64.ARM64_REG_X7:  r('x7',  64),
            capstone.arm64.ARM64_REG_X8:  r('x8',  64),
            capstone.arm64.ARM64_REG_X9:  r('x9',  64),
            capstone.arm64.ARM64_REG_X10: r('x10', 64),
            capstone.arm64.ARM64_REG_X11: r('x11', 64),
            capstone.arm64.ARM64_REG_X12: r('x12', 64),
            capstone.arm64.ARM64_REG_X13: r('x13', 64),
            capstone.arm64.ARM64_REG_X14: r('x14', 64),
            capstone.arm64.ARM64_REG_X15: r('x15', 64),
            capstone.arm64.ARM64_REG_X16: r('x16', 64),
            capstone.arm64.ARM64_REG_X17: r('x17', 64),
            capstone.arm64.ARM64_REG_X18: r('x18', 64),
            capstone.arm64.ARM64_REG_X19: r('x19', 64),
            capstone.arm64.ARM64_REG_X20: r('x20', 64),
            capstone.arm64.ARM64_REG_X21: r('x21', 64),
            capstone.arm64.ARM64_REG_X22: r('x22', 64),
            capstone.arm64.ARM64_REG_X23: r('x23', 64),
            capstone.arm64.ARM64_REG_X24: r('x24', 64),
            capstone.arm64.ARM64_REG_X25: r('x25', 64),
            capstone.arm64.ARM64_REG_X26: r('x26', 64),
            capstone.arm64.ARM64_REG_X27: r('x27', 64),
            capstone.arm64.ARM64_REG_X28: r('x28', 64),
            capstone.arm64.ARM64_REG_X29: r('x29', 64),
            capstone.arm64.ARM64_REG_X30: r('x30', 64),
            capstone.arm64.ARM64_REG_SP:  r('sp',  64),
            capstone.arm64.ARM64_REG_LR:  r('lr',  64),
        }

        self.word_size = 64
        self.stack_ptr = self.registers[capstone.arm64.ARM64_REG_SP]
        self.link_reg = self.registers[capstone.arm64.ARM64_REG_LR]
        self.program_ctr = r('pc', 64)
        self.disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self.disassembler.detail = True


def translate(code_bytes, base_address):
    done = False
    ctx = Arm64TranslationContext()

    for i in ctx.disassembler.disasm(code_bytes, base_address):

        if done:
            raise StopIteration()

        mnemonic = '{} {}'.format(i.mnemonic, i.op_str)
        yield native.Instruction(
            i.address, mnemonic, _translate(ctx, i),
            ends_basic_block(i), i.size)

        if ends_basic_block(i):
            done = True
