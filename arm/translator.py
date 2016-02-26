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

"""reil.arm.translator - ARM translator

This module generates REIL (reverse engineering intermediate language)
IL from ARMv7/Thumbv2 machine code.
"""


import capstone

import reil.native as native
from reil.shorthand import *

import reil.arm.arithmetic as arithmetic
import reil.arm.control_flow as control_flow
import reil.arm.memory as memory
import reil.arm.privileged as privileged

opcode_handlers = {
  capstone.arm.ARM_INS_ADD:  arithmetic.arm_add,
  capstone.arm.ARM_INS_B:    control_flow.arm_b,
  capstone.arm.ARM_INS_BLX:  control_flow.arm_blx,
  capstone.arm.ARM_INS_CMP:  arithmetic.arm_sub,
  capstone.arm.ARM_INS_MOV:  memory.arm_mov,
  capstone.arm.ARM_INS_MOVT: memory.arm_movt,
  capstone.arm.ARM_INS_MOVW: memory.arm_movw,
  capstone.arm.ARM_INS_MSR:  privileged.arm_msr,
  capstone.arm.ARM_INS_PUSH: memory.arm_push,
  capstone.arm.ARM_INS_STR:  memory.arm_str,
  capstone.arm.ARM_INS_SUB:  arithmetic.arm_sub,
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


class ArmTranslationContext(TranslationContext):

    def __init__(self):
        TranslationContext.__init__(self)

        self.registers = {
            capstone.arm.ARM_REG_R0:    r('r0', 32),
            capstone.arm.ARM_REG_R1:    r('r1', 32),
            capstone.arm.ARM_REG_R2:    r('r2', 32),
            capstone.arm.ARM_REG_R3:    r('r3', 32),
            capstone.arm.ARM_REG_R4:    r('r4', 32),
            capstone.arm.ARM_REG_R5:    r('r5', 32),
            capstone.arm.ARM_REG_R6:    r('r6', 32),
            capstone.arm.ARM_REG_R7:    r('r7', 32),
            capstone.arm.ARM_REG_R8:    r('r8', 32),
            capstone.arm.ARM_REG_R9:    r('r9', 32),
            capstone.arm.ARM_REG_R10:   r('r10', 32),
            capstone.arm.ARM_REG_R11:   r('r11', 32),
            capstone.arm.ARM_REG_R13:   r('sp', 32),
            capstone.arm.ARM_REG_R14:   r('lr', 32),
            capstone.arm.ARM_REG_R15:   r('pc', 32),
        }

        self.word_size = 32
        self.thumb = False
        self.stack_ptr = self.registers[capstone.arm.ARM_REG_R13]
        self.link_reg = self.registers[capstone.arm.ARM_REG_R14]
        self.program_ctr = self.registers[capstone.arm.ARM_REG_R15]
        self.disassembler = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.disassembler.detail = True


class ThumbTranslationContext(TranslationContext):

    def __init__(self):
        TranslationContext.__init__(self)

        self.registers = {
            capstone.arm.ARM_REG_R0:    r('r0', 32),
            capstone.arm.ARM_REG_R1:    r('r1', 32),
            capstone.arm.ARM_REG_R2:    r('r2', 32),
            capstone.arm.ARM_REG_R3:    r('r3', 32),
            capstone.arm.ARM_REG_R4:    r('r4', 32),
            capstone.arm.ARM_REG_R5:    r('r5', 32),
            capstone.arm.ARM_REG_R6:    r('r6', 32),
            capstone.arm.ARM_REG_R7:    r('r7', 32),
            capstone.arm.ARM_REG_R8:    r('r8', 32),
            capstone.arm.ARM_REG_R9:    r('r9', 32),
            capstone.arm.ARM_REG_R10:   r('r10', 32),
            capstone.arm.ARM_REG_R11:   r('r11', 32),
            capstone.arm.ARM_REG_R13:   r('sp', 32),
            capstone.arm.ARM_REG_R14:   r('lr', 32),
            capstone.arm.ARM_REG_R15:   r('pc', 32),
        }

        self.word_size = 32
        self.thumb = True
        self.stack_ptr = self.registers[capstone.arm.ARM_REG_R13]
        self.link_reg = self.registers[capstone.arm.ARM_REG_R14]
        self.program_ctr = self.registers[capstone.arm.ARM_REG_R15]
        self.disassembler = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self.disassembler.detail = True


def translate(code_bytes, base_address, thumb=False):
    done = False

    if thumb:
        ctx = ThumbTranslationContext()
    else:
        ctx = ArmTranslationContext()

    for i in ctx.disassembler.disasm(code_bytes, base_address):

        if done:
            raise StopIteration()

        mnemonic = '{} {}'.format(i.mnemonic, i.op_str)
        yield native.Instruction(
            i.address, mnemonic, _translate(ctx, i),
            ends_basic_block(i), i.size)

        if ends_basic_block(i):
            done = True
