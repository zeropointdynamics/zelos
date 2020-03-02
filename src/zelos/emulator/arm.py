# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================
import unicorn.arm_const as uc

from .base import IEmuHelper


class ArmEmuHelper(IEmuHelper):
    ip_reg = "pc"
    sp_reg = "sp"
    fp_reg = "fp"
    regmap = {
        "apsr": uc.UC_ARM_REG_APSR,
        "apsr_nzcv": uc.UC_ARM_REG_APSR_NZCV,
        "cpsr": uc.UC_ARM_REG_CPSR,
        "fpexc": uc.UC_ARM_REG_FPEXC,
        "fpinst": uc.UC_ARM_REG_FPINST,
        "fpscr": uc.UC_ARM_REG_FPSCR,
        "fpscr_nzcv": uc.UC_ARM_REG_FPSCR_NZCV,
        "fpsid": uc.UC_ARM_REG_FPSID,
        "itstate": uc.UC_ARM_REG_ITSTATE,
        "lr": uc.UC_ARM_REG_LR,
        "pc": uc.UC_ARM_REG_PC,
        "sp": uc.UC_ARM_REG_SP,
        "spsr": uc.UC_ARM_REG_SPSR,
        "d0": uc.UC_ARM_REG_D0,
        "d1": uc.UC_ARM_REG_D1,
        "d2": uc.UC_ARM_REG_D2,
        "d3": uc.UC_ARM_REG_D3,
        "d4": uc.UC_ARM_REG_D4,
        "d5": uc.UC_ARM_REG_D5,
        "d6": uc.UC_ARM_REG_D6,
        "d7": uc.UC_ARM_REG_D7,
        "d8": uc.UC_ARM_REG_D8,
        "d9": uc.UC_ARM_REG_D9,
        "d10": uc.UC_ARM_REG_D10,
        "d11": uc.UC_ARM_REG_D11,
        "d12": uc.UC_ARM_REG_D12,
        "d13": uc.UC_ARM_REG_D13,
        "d14": uc.UC_ARM_REG_D14,
        "d15": uc.UC_ARM_REG_D15,
        "d16": uc.UC_ARM_REG_D16,
        "d17": uc.UC_ARM_REG_D17,
        "d18": uc.UC_ARM_REG_D18,
        "d19": uc.UC_ARM_REG_D19,
        "d20": uc.UC_ARM_REG_D20,
        "d21": uc.UC_ARM_REG_D21,
        "d22": uc.UC_ARM_REG_D22,
        "d23": uc.UC_ARM_REG_D23,
        "d24": uc.UC_ARM_REG_D24,
        "d25": uc.UC_ARM_REG_D25,
        "d26": uc.UC_ARM_REG_D26,
        "d27": uc.UC_ARM_REG_D27,
        "d28": uc.UC_ARM_REG_D28,
        "d29": uc.UC_ARM_REG_D29,
        "d30": uc.UC_ARM_REG_D30,
        "d31": uc.UC_ARM_REG_D31,
        "fpinst2": uc.UC_ARM_REG_FPINST2,
        "mvfr0": uc.UC_ARM_REG_MVFR0,
        "mvfr1": uc.UC_ARM_REG_MVFR1,
        "mvfr2": uc.UC_ARM_REG_MVFR2,
        "q0": uc.UC_ARM_REG_Q0,
        "q1": uc.UC_ARM_REG_Q1,
        "q2": uc.UC_ARM_REG_Q2,
        "q3": uc.UC_ARM_REG_Q3,
        "q4": uc.UC_ARM_REG_Q4,
        "q5": uc.UC_ARM_REG_Q5,
        "q6": uc.UC_ARM_REG_Q6,
        "q7": uc.UC_ARM_REG_Q7,
        "q8": uc.UC_ARM_REG_Q8,
        "q9": uc.UC_ARM_REG_Q9,
        "q10": uc.UC_ARM_REG_Q10,
        "q11": uc.UC_ARM_REG_Q11,
        "q12": uc.UC_ARM_REG_Q12,
        "q13": uc.UC_ARM_REG_Q13,
        "q14": uc.UC_ARM_REG_Q14,
        "q15": uc.UC_ARM_REG_Q15,
        "r0": uc.UC_ARM_REG_R0,
        "r1": uc.UC_ARM_REG_R1,
        "r2": uc.UC_ARM_REG_R2,
        "r3": uc.UC_ARM_REG_R3,
        "r4": uc.UC_ARM_REG_R4,
        "r5": uc.UC_ARM_REG_R5,
        "r6": uc.UC_ARM_REG_R6,
        "r7": uc.UC_ARM_REG_R7,
        "r8": uc.UC_ARM_REG_R8,
        "r9": uc.UC_ARM_REG_R9,
        "r10": uc.UC_ARM_REG_R10,
        "r11": uc.UC_ARM_REG_R11,
        "r12": uc.UC_ARM_REG_R12,
        "s0": uc.UC_ARM_REG_S0,
        "s1": uc.UC_ARM_REG_S1,
        "s2": uc.UC_ARM_REG_S2,
        "s3": uc.UC_ARM_REG_S3,
        "s4": uc.UC_ARM_REG_S4,
        "s5": uc.UC_ARM_REG_S5,
        "s6": uc.UC_ARM_REG_S6,
        "s7": uc.UC_ARM_REG_S7,
        "s8": uc.UC_ARM_REG_S8,
        "s9": uc.UC_ARM_REG_S9,
        "s10": uc.UC_ARM_REG_S10,
        "s11": uc.UC_ARM_REG_S11,
        "s12": uc.UC_ARM_REG_S12,
        "s13": uc.UC_ARM_REG_S13,
        "s14": uc.UC_ARM_REG_S14,
        "s15": uc.UC_ARM_REG_S15,
        "s16": uc.UC_ARM_REG_S16,
        "s17": uc.UC_ARM_REG_S17,
        "s18": uc.UC_ARM_REG_S18,
        "s19": uc.UC_ARM_REG_S19,
        "s20": uc.UC_ARM_REG_S20,
        "s21": uc.UC_ARM_REG_S21,
        "s22": uc.UC_ARM_REG_S22,
        "s23": uc.UC_ARM_REG_S23,
        "s24": uc.UC_ARM_REG_S24,
        "s25": uc.UC_ARM_REG_S25,
        "s26": uc.UC_ARM_REG_S26,
        "s27": uc.UC_ARM_REG_S27,
        "s28": uc.UC_ARM_REG_S28,
        "s29": uc.UC_ARM_REG_S29,
        "s30": uc.UC_ARM_REG_S30,
        "s31": uc.UC_ARM_REG_S31,
        "c1_c0_2": uc.UC_ARM_REG_C1_C0_2,
        "c13_c0_2": uc.UC_ARM_REG_C13_C0_2,
        "c13_c0_3": uc.UC_ARM_REG_C13_C0_3,
        "ipsr": uc.UC_ARM_REG_IPSR,
        "msp": uc.UC_ARM_REG_MSP,
        "psp": uc.UC_ARM_REG_PSP,
        "control": uc.UC_ARM_REG_CONTROL,
        "ending": uc.UC_ARM_REG_ENDING,
        # alias registers
        "r13": uc.UC_ARM_REG_R13,
        "r14": uc.UC_ARM_REG_R14,
        "r15": uc.UC_ARM_REG_R15,
        "sb": uc.UC_ARM_REG_SB,
        "sl": uc.UC_ARM_REG_SL,
        "fp": uc.UC_ARM_REG_FP,
        "ip": uc.UC_ARM_REG_IP,
    }

    # These are the default registers that should be printed
    # when debugging
    imp_regs = [
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "sp",
        "lr",
        "pc",
        "cpsr",
        "fp",
        "fpscr",
        "fpsid",
        "fpexc",
    ]

    def __init__(self, unicorn, state):
        super().__init__(unicorn, state)
        # Enables arm VFP:
        #   https://github.com/unicorn-engine/unicorn/pull/684
        tmp_val = self.get_reg("c1_c0_2")
        tmp_val |= 0xF << 20
        self.set_reg("c1_c0_2", tmp_val)
        self.set_reg("fpexc", 0x40000000)
