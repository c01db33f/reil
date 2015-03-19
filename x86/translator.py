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

"""reil.x86.sse - x86 and x86_64 translators

This module generates REIL (reverse engineering intermediate language)
IL from x86 and x86_64 machine code.

This file is responsible for translation of instructions that belong to
the streaming-simd extensions
"""


import capstone

import reil.native as native
from reil.shorthand import *

import reil.x86.ascii as ascii
import reil.x86.arithmetic as arithmetic
import reil.x86.bitwise as bitwise
import reil.x86.control_flow as control_flow
import reil.x86.logic as logic
import reil.x86.memory as memory
import reil.x86.misc as misc
import reil.x86.sse as sse
import reil.x86.unsupported as unsupported

opcode_handlers = {

    capstone.x86.X86_INS_AAA:       ascii.x86_aaa,
    capstone.x86.X86_INS_AAD:       ascii.x86_aad,
    capstone.x86.X86_INS_AAS:       ascii.x86_aas,
    capstone.x86.X86_INS_ADC:       arithmetic.x86_adc,
    capstone.x86.X86_INS_ADD:       arithmetic.x86_add,
    capstone.x86.X86_INS_ADDPD:     unsupported.floating_point,
    capstone.x86.X86_INS_ADDPS:     unsupported.floating_point,
    capstone.x86.X86_INS_ADDSD:     unsupported.floating_point,
    capstone.x86.X86_INS_ADDSS:     unsupported.floating_point,
    capstone.x86.X86_INS_ADDSUBPD:  unsupported.floating_point,
    capstone.x86.X86_INS_ADDSUBPS:  unsupported.floating_point,
    capstone.x86.X86_INS_AND:       logic.x86_and,
    capstone.x86.X86_INS_ANDPD:     unsupported.floating_point,
    capstone.x86.X86_INS_ANDPS:     unsupported.floating_point,
    capstone.x86.X86_INS_ANDNPD:    unsupported.floating_point,
    capstone.x86.X86_INS_ANDNPS:    unsupported.floating_point,
    capstone.x86.X86_INS_ARPL:      misc.x86_arpl,

    capstone.x86.X86_INS_BOUND:     unsupported.requires_exceptions,
    capstone.x86.X86_INS_BSF:       bitwise.x86_bsf,
    capstone.x86.X86_INS_BSR:       bitwise.x86_bsr,
    capstone.x86.X86_INS_BSWAP:     misc.x86_bswap,
    capstone.x86.X86_INS_BT:        bitwise.x86_bt,
    capstone.x86.X86_INS_BTC:       bitwise.x86_btc,
    capstone.x86.X86_INS_BTR:       bitwise.x86_btr,
    capstone.x86.X86_INS_BTS:       bitwise.x86_bts,

    capstone.x86.X86_INS_CALL:      control_flow.x86_call,
    capstone.x86.X86_INS_CBW:       misc.x86_cbw,
    capstone.x86.X86_INS_CQO:       misc.x86_cqo,
    capstone.x86.X86_INS_CLC:       misc.x86_clc,
    capstone.x86.X86_INS_CLD:       misc.x86_cld,
    capstone.x86.X86_INS_CLFLUSH:   unsupported.low_level,
    capstone.x86.X86_INS_CLI:       unsupported.privileged,
    capstone.x86.X86_INS_CLTS:      unsupported.privileged,
    capstone.x86.X86_INS_CMC:       misc.x86_cmc,
    capstone.x86.X86_INS_CMOVA:     memory.x86_cmova,
    capstone.x86.X86_INS_CMOVAE:    memory.x86_cmovae,
    capstone.x86.X86_INS_CMOVB:     memory.x86_cmovb,
    capstone.x86.X86_INS_CMOVBE:    memory.x86_cmovbe,
    capstone.x86.X86_INS_CMOVE:     memory.x86_cmove,
    capstone.x86.X86_INS_CMOVG:     memory.x86_cmovg,
    capstone.x86.X86_INS_CMOVGE:    memory.x86_cmovge,
    capstone.x86.X86_INS_CMOVL:     memory.x86_cmovl,
    capstone.x86.X86_INS_CMOVLE:    memory.x86_cmovle,
    capstone.x86.X86_INS_CMOVNE:    memory.x86_cmovne,
    capstone.x86.X86_INS_CMOVNO:    memory.x86_cmovno,
    capstone.x86.X86_INS_CMOVNP:    memory.x86_cmovnp,
    capstone.x86.X86_INS_CMOVNS:    memory.x86_cmovns,
    capstone.x86.X86_INS_CMOVO:     memory.x86_cmovo,
    capstone.x86.X86_INS_CMOVP:     memory.x86_cmovp,
    capstone.x86.X86_INS_CMOVS:     memory.x86_cmovs,
    capstone.x86.X86_INS_CMP:       arithmetic.x86_cmp,
    capstone.x86.X86_INS_CMPPD:     unsupported.floating_point,
    capstone.x86.X86_INS_CMPPS:     unsupported.floating_point,
    capstone.x86.X86_INS_CMPSB:     memory.x86_cmpsb,
    capstone.x86.X86_INS_CMPSW:     memory.x86_cmpsw,
    capstone.x86.X86_INS_CMPSD:     memory.x86_cmpsd,
    capstone.x86.X86_INS_CMPSQ:     memory.x86_cmpsq,

    # TODO: figure out what is happening with capstone interpretation for the
    # CMPSD xmmx, xmmy, i instructions
    # ie CMPEQSD xmm0, xmm1
    # and CMPSS instructions.

    capstone.x86.X86_INS_CMPXCHG:   misc.x86_cmpxchg,
    capstone.x86.X86_INS_CMPXCHG8B: misc.x86_cmpxchg8b,
    capstone.x86.X86_INS_COMISD:    unsupported.floating_point,
    capstone.x86.X86_INS_COMISS:    unsupported.floating_point,
    capstone.x86.X86_INS_CPUID:     misc.x86_cpuid,
    capstone.x86.X86_INS_CVTDQ2PD:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTDQ2PS:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPD2DQ:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPD2PI:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPD2PS:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPI2PD:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPI2PS:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPS2DQ:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPS2PD:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTPS2PI:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTSD2SI:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTSD2SS:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTSI2SD:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTSI2SS:  unsupported.floating_point,
    capstone.x86.X86_INS_CVTTPD2PI: unsupported.floating_point,
    capstone.x86.X86_INS_CVTTPD2DQ: unsupported.floating_point,
    capstone.x86.X86_INS_CVTTPS2DQ: unsupported.floating_point,
    capstone.x86.X86_INS_CVTTPS2PI: unsupported.floating_point,
    capstone.x86.X86_INS_CVTTSD2SI: unsupported.floating_point,
    capstone.x86.X86_INS_CVTTSS2SI: unsupported.floating_point,
    capstone.x86.X86_INS_CWD:       misc.x86_cwd,
    capstone.x86.X86_INS_CWDE:      misc.x86_cwde,
    capstone.x86.X86_INS_CDQ:       misc.x86_cdq,
    capstone.x86.X86_INS_CDQE:      misc.x86_cdqe,

    capstone.x86.X86_INS_DAA:       ascii.x86_daa,
    capstone.x86.X86_INS_DAS:       ascii.x86_das,
    capstone.x86.X86_INS_DEC:       arithmetic.x86_dec,
    capstone.x86.X86_INS_DIV:       arithmetic.x86_div,
    capstone.x86.X86_INS_DIVPD:     unsupported.floating_point,
    capstone.x86.X86_INS_DIVPS:     unsupported.floating_point,
    capstone.x86.X86_INS_DIVSD:     unsupported.floating_point,
    capstone.x86.X86_INS_DIVSS:     unsupported.floating_point,

    capstone.x86.X86_INS_IDIV:      arithmetic.x86_idiv,
    capstone.x86.X86_INS_IMUL:      arithmetic.x86_imul,
    capstone.x86.X86_INS_INC:       arithmetic.x86_inc,
    capstone.x86.X86_INS_INT:       misc.x86_int,

    capstone.x86.X86_INS_JA:        control_flow.x86_ja,
    capstone.x86.X86_INS_JAE:       control_flow.x86_jae,
    capstone.x86.X86_INS_JB:        control_flow.x86_jb,
    capstone.x86.X86_INS_JBE:       control_flow.x86_jbe,
    capstone.x86.X86_INS_JCXZ:      control_flow.x86_jcxz,
    capstone.x86.X86_INS_JECXZ:     control_flow.x86_jecxz,
    capstone.x86.X86_INS_JRCXZ:     control_flow.x86_jrcxz,
    capstone.x86.X86_INS_JE:        control_flow.x86_je,
    capstone.x86.X86_INS_JG:        control_flow.x86_jg,
    capstone.x86.X86_INS_JGE:       control_flow.x86_jge,
    capstone.x86.X86_INS_JL:        control_flow.x86_jl,
    capstone.x86.X86_INS_JLE:       control_flow.x86_jle,
    capstone.x86.X86_INS_JMP:       control_flow.x86_jmp,
    capstone.x86.X86_INS_JNE:       control_flow.x86_jne,
    capstone.x86.X86_INS_JNO:       control_flow.x86_jno,
    capstone.x86.X86_INS_JNP:       control_flow.x86_jnp,
    capstone.x86.X86_INS_JNS:       control_flow.x86_jns,
    capstone.x86.X86_INS_JO:        control_flow.x86_jo,
    capstone.x86.X86_INS_JP:        control_flow.x86_jp,
    capstone.x86.X86_INS_JS:        control_flow.x86_js,

    capstone.x86.X86_INS_LEA:       memory.x86_lea,
    capstone.x86.X86_INS_LEAVE:     memory.x86_leave,
    capstone.x86.X86_INS_MOV:       memory.x86_mov,
    capstone.x86.X86_INS_MOVABS:    memory.x86_movabs,
    capstone.x86.X86_INS_MOVAPS:    sse.x86_movaps,
    capstone.x86.X86_INS_MOVD:      sse.x86_movd,
    capstone.x86.X86_INS_MOVDQA:    sse.x86_movdqa,
    capstone.x86.X86_INS_MOVDQU:    sse.x86_movdqu,
    capstone.x86.X86_INS_MOVHPD:    sse.x86_movhpd,
    capstone.x86.X86_INS_MOVLPD:    sse.x86_movlpd,
    capstone.x86.X86_INS_MOVQ:      sse.x86_movq,
    capstone.x86.X86_INS_MOVSB:     memory.x86_movsb,
    capstone.x86.X86_INS_MOVSD:     memory.x86_movsd,
    capstone.x86.X86_INS_MOVSQ:     memory.x86_movsq,
    capstone.x86.X86_INS_MOVSW:     memory.x86_movsw,
    capstone.x86.X86_INS_MOVSX:     memory.x86_movsx,
    capstone.x86.X86_INS_MOVSXD:    memory.x86_movsx,
    capstone.x86.X86_INS_MOVUPS:    sse.x86_movups,
    capstone.x86.X86_INS_MOVZX:     memory.x86_movzx,
    capstone.x86.X86_INS_MUL:       arithmetic.x86_mul,
    capstone.x86.X86_INS_NEG:       arithmetic.x86_neg,
    capstone.x86.X86_INS_NOP:       misc.x86_nop,
    capstone.x86.X86_INS_NOT:       logic.x86_not,
    capstone.x86.X86_INS_OR:        logic.x86_or,
    capstone.x86.X86_INS_PALIGNR:   sse.x86_palignr,
    capstone.x86.X86_INS_PCMPEQB:   sse.x86_pcmpeqb,
    capstone.x86.X86_INS_PMOVMSKB:  sse.x86_pmovmskb,
    capstone.x86.X86_INS_POP:       memory.x86_pop,
    capstone.x86.X86_INS_POR:       sse.x86_por,
    capstone.x86.X86_INS_PSHUFD:    sse.x86_pshufd,
    capstone.x86.X86_INS_PSLLDQ:    sse.x86_pslldq,
    capstone.x86.X86_INS_PSUBB:     sse.x86_psubb,
    capstone.x86.X86_INS_PSUBW:     sse.x86_psubw,
    capstone.x86.X86_INS_PSUBD:     sse.x86_psubd,
    capstone.x86.X86_INS_PSUBQ:     sse.x86_psubq,
    capstone.x86.X86_INS_PUNPCKLBW: sse.x86_punpcklbw,
    capstone.x86.X86_INS_PUNPCKLWD: sse.x86_punpcklwd,
    capstone.x86.X86_INS_PUNPCKLDQ: sse.x86_punpckldq,
    capstone.x86.X86_INS_PUNPCKLQDQ:sse.x86_punpcklqdq,
    capstone.x86.X86_INS_PUSH:      memory.x86_push,
    capstone.x86.X86_INS_PXOR:      sse.x86_pxor,
    capstone.x86.X86_INS_RET:       control_flow.x86_ret,
    capstone.x86.X86_INS_RDTSC:     misc.x86_rdtsc,
    capstone.x86.X86_INS_ROL:       bitwise.x86_rol,
    capstone.x86.X86_INS_ROR:       bitwise.x86_ror,
    capstone.x86.X86_INS_SAR:       bitwise.x86_sar,
    capstone.x86.X86_INS_SBB:       arithmetic.x86_sbb,
    capstone.x86.X86_INS_SCASB:     memory.x86_scasb,
    capstone.x86.X86_INS_SCASD:     memory.x86_scasd,
    capstone.x86.X86_INS_SCASQ:     memory.x86_scasq,
    capstone.x86.X86_INS_SCASW:     memory.x86_scasw,

    capstone.x86.X86_INS_SETA:      misc.x86_seta,
    capstone.x86.X86_INS_SETAE:     misc.x86_setae,
    capstone.x86.X86_INS_SETB:      misc.x86_setb,
    capstone.x86.X86_INS_SETBE:     misc.x86_setbe,
    capstone.x86.X86_INS_SETE:      misc.x86_sete,
    capstone.x86.X86_INS_SETG:      misc.x86_setg,
    capstone.x86.X86_INS_SETGE:     misc.x86_setge,
    capstone.x86.X86_INS_SETL:      misc.x86_setl,
    capstone.x86.X86_INS_SETLE:     misc.x86_setle,
    capstone.x86.X86_INS_SETNE:     misc.x86_setne,
    capstone.x86.X86_INS_SETNO:     misc.x86_setno,
    capstone.x86.X86_INS_SETNP:     misc.x86_setnp,
    capstone.x86.X86_INS_SETNS:     misc.x86_setns,
    capstone.x86.X86_INS_SETO:      misc.x86_seto,
    capstone.x86.X86_INS_SETP:      misc.x86_setp,
    capstone.x86.X86_INS_SETS:      misc.x86_sets,

    capstone.x86.X86_INS_SHL:       bitwise.x86_shl,
    capstone.x86.X86_INS_SHR:       bitwise.x86_shr,
    capstone.x86.X86_INS_SHRD:      bitwise.x86_shrd,
    capstone.x86.X86_INS_STOSB:     memory.x86_stosb,
    capstone.x86.X86_INS_STOSD:     memory.x86_stosd,
    capstone.x86.X86_INS_STOSQ:     memory.x86_stosq,
    capstone.x86.X86_INS_STOSW:     memory.x86_stosw,
    capstone.x86.X86_INS_SUB:       arithmetic.x86_sub,
    capstone.x86.X86_INS_SYSENTER:  misc.x86_sysenter,
    capstone.x86.X86_INS_SYSCALL:   misc.x86_syscall,
    capstone.x86.X86_INS_TEST:      logic.x86_test,
    capstone.x86.X86_INS_VMOVDQA:   sse.x86_movdqa,
    capstone.x86.X86_INS_VMOVDQU:   sse.x86_movdqu,
    capstone.x86.X86_INS_XCHG:      misc.x86_xchg,
    capstone.x86.X86_INS_XOR:       logic.x86_xor,
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
    #print_instruction(i)
    #print(i.id)
    #raise NotImplementedError()

    ctx.emit(  unkn_())


def _translate(ctx, i):
    if i.id in opcode_handlers:
        #print_instruction(i)
        opcode_handlers[i.id](ctx, i)
    else:
        unknown_opcode(ctx, i)

    return ctx.finalise()


def ends_basic_block(i):
    other_flow_control = {
        capstone.x86.X86_INS_CALL,
        capstone.x86.X86_INS_RET
    }
    if capstone.x86.X86_GRP_JUMP in i.groups:
        return True
    elif i.id in other_flow_control:
        return True
    return False


class X86TranslationContext(TranslationContext):

    def __init__(self):
        TranslationContext.__init__(self)

        self.registers = {
            capstone.x86.X86_REG_EAX:   r('eax', 32),
            capstone.x86.X86_REG_EBX:   r('ebx', 32),
            capstone.x86.X86_REG_ECX:   r('ecx', 32),
            capstone.x86.X86_REG_EDX:   r('edx', 32),
            capstone.x86.X86_REG_ESI:   r('esi', 32),
            capstone.x86.X86_REG_EDI:   r('edi', 32),
            capstone.x86.X86_REG_EBP:   r('ebp', 32),
            capstone.x86.X86_REG_ESP:   r('esp', 32),

            capstone.x86.X86_REG_FS:    r('fsbase', 32),
            capstone.x86.X86_REG_GS:    r('gsbase', 32),
            capstone.x86.X86_REG_CS:    r('csbase', 32),
            capstone.x86.X86_REG_SS:    r('ssbase', 32),
            capstone.x86.X86_REG_DS:    r('dsbase', 32),
            capstone.x86.X86_REG_ES:    r('esbase', 32),

            capstone.x86.X86_REG_XMM0:  r('xmm0', 128),
            capstone.x86.X86_REG_XMM1:  r('xmm1', 128),
            capstone.x86.X86_REG_XMM2:  r('xmm2', 128),
            capstone.x86.X86_REG_XMM3:  r('xmm3', 128),
            capstone.x86.X86_REG_XMM4:  r('xmm4', 128),
            capstone.x86.X86_REG_XMM5:  r('xmm5', 128),
            capstone.x86.X86_REG_XMM6:  r('xmm6', 128),
            capstone.x86.X86_REG_XMM7:  r('xmm7', 128),
        }

        self.word_size = 32
        self.accumulator = self.registers[capstone.x86.X86_REG_EAX]
        self.base = self.registers[capstone.x86.X86_REG_EBX]
        self.counter = self.registers[capstone.x86.X86_REG_ECX]
        self.data = self.registers[capstone.x86.X86_REG_EDX]
        self.source = self.registers[capstone.x86.X86_REG_ESI]
        self.destination = self.registers[capstone.x86.X86_REG_EDI]
        self.frame_ptr = self.registers[capstone.x86.X86_REG_EBP]
        self.stack_ptr = self.registers[capstone.x86.X86_REG_ESP]
        self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.disassembler.detail = True


class X86_64TranslationContext(TranslationContext):

    def __init__(self):
        TranslationContext.__init__(self)

        self.registers = {
            capstone.x86.X86_REG_RAX:   r('rax', 64),
            capstone.x86.X86_REG_RBX:   r('rbx', 64),
            capstone.x86.X86_REG_RCX:   r('rcx', 64),
            capstone.x86.X86_REG_RDX:   r('rdx', 64),
            capstone.x86.X86_REG_RSI:   r('rsi', 64),
            capstone.x86.X86_REG_RDI:   r('rdi', 64),
            capstone.x86.X86_REG_RBP:   r('rbp', 64),
            capstone.x86.X86_REG_RSP:   r('rsp', 64),
            capstone.x86.X86_REG_R8:    r('r8', 64),
            capstone.x86.X86_REG_R9:    r('r9', 64),
            capstone.x86.X86_REG_R10:   r('r10', 64),
            capstone.x86.X86_REG_R11:   r('r11', 64),
            capstone.x86.X86_REG_R12:   r('r12', 64),
            capstone.x86.X86_REG_R13:   r('r13', 64),
            capstone.x86.X86_REG_R14:   r('r14', 64),
            capstone.x86.X86_REG_R15:   r('r15', 64),
            #capstone.x86.X86_REG_RIP:   r('rip', 64),

            capstone.x86.X86_REG_FS:    r('fsbase', 64),
            capstone.x86.X86_REG_GS:    r('gsbase', 64),

            capstone.x86.X86_REG_XMM0:  r('xmm0', 128),
            capstone.x86.X86_REG_XMM1:  r('xmm1', 128),
            capstone.x86.X86_REG_XMM2:  r('xmm2', 128),
            capstone.x86.X86_REG_XMM3:  r('xmm3', 128),
            capstone.x86.X86_REG_XMM4:  r('xmm4', 128),
            capstone.x86.X86_REG_XMM5:  r('xmm5', 128),
            capstone.x86.X86_REG_XMM6:  r('xmm6', 128),
            capstone.x86.X86_REG_XMM7:  r('xmm7', 128),
            capstone.x86.X86_REG_XMM8:  r('xmm8', 128),
            capstone.x86.X86_REG_XMM9:  r('xmm9', 128),
            capstone.x86.X86_REG_XMM10: r('xmm10', 128),
            capstone.x86.X86_REG_XMM11: r('xmm11', 128),
            capstone.x86.X86_REG_XMM12: r('xmm12', 128),
            capstone.x86.X86_REG_XMM13: r('xmm13', 128),
            capstone.x86.X86_REG_XMM14: r('xmm14', 128),
            capstone.x86.X86_REG_XMM15: r('xmm15', 128),
        }

        self.word_size = 64
        self.accumulator = self.registers[capstone.x86.X86_REG_RAX]
        self.base = self.registers[capstone.x86.X86_REG_RBX]
        self.counter = self.registers[capstone.x86.X86_REG_RCX]
        self.data = self.registers[capstone.x86.X86_REG_RDX]
        self.source = self.registers[capstone.x86.X86_REG_RSI]
        self.destination = self.registers[capstone.x86.X86_REG_RDI]
        self.frame_ptr = self.registers[capstone.x86.X86_REG_RBP]
        self.stack_ptr = self.registers[capstone.x86.X86_REG_RSP]
        self.disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.disassembler.detail = True


#_x86_ctx = X86TranslationContext()
#_x86_64_ctx = X86_64TranslationContext()


def translate(code_bytes, base_address, x86_64=False):
    done = False

    if x86_64:
        ctx = X86_64TranslationContext()
    else:
        ctx = X86TranslationContext()

    for i in ctx.disassembler.disasm(code_bytes, base_address):

        if done:
            raise StopIteration()

        mnemonic = '{} {}'.format(i.mnemonic, i.op_str)
        yield native.Instruction(
            i.address, mnemonic, _translate(ctx, i),
            ends_basic_block(i), i.size)

        if ends_basic_block(i):
            done = True