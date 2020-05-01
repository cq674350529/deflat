#!/usr/bin/env python3

import struct
import hashlib

ARCH_X86 = {"X86", "AMD64"}
ARCH_ARM = {"ARMEL", "ARMHF"}
ARCH_ARM64 = {'AARCH64'}

OPCODES = {
    'x86':
        {
            'a': b'\x87', 'ae': b'\x83', 'b': b'\x82', 'be': b'\x86', 'c': b'\x82', 'e': b'\x84', 'z': b'\x84', 'g': b'\x8F', 'ge': b'\x8D', 'l': b'\x8C', 'le': b'\x8E', 'na': b'\x86', 'nae': b'\x82', 'nb': b'\x83', 'nbe': b'\x87', 'nc': b'\x83', 'ne': b'\x85', 'ng': b'\x8E', 'nge': b'\x8C', 'nl': b'\x8D', 'nle': b'\x8F', 'no': 'b\x81', 'np': b'\x8B', 'ns': b'\x89', 'nz': b'\x85', 'o': b'\x80', 'p': b'\x8A', 'pe': b'\x8A', 'po': b'\x8B', 's': b'\x88', 'nop': b'\x90', 'jmp': b'\xE9', 'j': b'\x0F'
         },
    'arm':
        {
            'nop': b'\x00\xF0\x20\xE3', 'b': b'\xEA', 'blt': b'\xBA', 'beq': b'\x0A', 'bne': b'\x1A', 'bgt': b'\xCA', 'bhi': b'\x8A', 'bls': b'\x9A', 'ble': b'\xDA', 'bge': b'\xAA'
        },
    'arm64':
        {
            'nop': b'\x1F\x20\x03\xD5', 'b': b'\x14', 'b_cond':{'eq': 0x0, 'ne': 0x1, 'hs': 0x2, 'lo': 0x3, 'mi': 0x4, 'pl': 0x5, 'vs': 0x6, 'vc': 0x7, 'hi': 0x8, 'ls': 0x9, 'ge': 0xA, 'lt': 0xB, 'gt':0xC, 'le':0xD}
        }
}


def fill_nop(data, start_addr, length, arch):
    if arch.name in ARCH_X86:
        for i in range(0, length):
            data[start_addr + i] = ord(OPCODES['x86']['nop'])
    elif arch.name in ARCH_ARM | ARCH_ARM64:
        if arch.name in ARCH_ARM:
            nop_value = OPCODES['arm']['nop']
        else:
            nop_value = OPCODES['arm64']['nop']

        if arch.memory_endness == "Iend_BE":
            nop_value = nop_value[::-1]
        for i in range(0, length, 4):
            data[start_addr+i] = nop_value[0]
            data[start_addr+i+1] = nop_value[1]
            data[start_addr+i+2] = nop_value[2]
            data[start_addr+i+3] = nop_value[3]


def patch_instruction(data, offset, value):
    for i in range(len(value)):
        data[offset+i] = value[i]


"""
get the hex of j/b_jmp ins
"""
def ins_j_jmp_hex_x86(cur_addr, target_addr, j_cond):
    if j_cond == 'jmp':
        j_opcode = OPCODES['x86']['jmp']
        j_ins_size = 5
    else:
        j_opcode = OPCODES['x86']['j'] + OPCODES['x86'][j_cond]
        j_ins_size = 6

    jmp_offset = target_addr - cur_addr - j_ins_size
    patch_ins_hex = j_opcode + struct.pack('<i', jmp_offset)
    return patch_ins_hex


def ins_b_jmp_hex_arm(cur_addr, target_addr, b_cond):
    b_offset = (target_addr - cur_addr - 4*2) // 4
    patch_ins_hex = struct.pack('<i', b_offset)[:-1] + OPCODES['arm'][b_cond]
    return patch_ins_hex


def ins_b_jmp_hex_arm64(cur_addr, target_addr, b_cond):
    if b_cond == 'b':
        # reference: https://blog.csdn.net/qianlong4526888/article/details/8247219
        if cur_addr > target_addr:
            patch_ins_hex = struct.pack('<I', ((0x14000000 | 0x03ffffff) - (cur_addr - target_addr) // 4))
        else:
            patch_ins_hex = struct.pack('<I', ((0x14000000 & 0xfc000000) + (target_addr - cur_addr) // 4))
    else:
        offset = (((target_addr - cur_addr) // 4) << 5) & 0x00ffffe0
        # XXX: The oppisite cond should be used instead of the original cond for aarch64/arm64
        opcode = OPCODES['arm64']['b_cond'][b_cond.lower()]
        if opcode % 2 == 0:
            opcode += 1
        else:
            opcode -= 1
        patch_ins_hex = struct.pack('<I', 0x54000000 | offset | opcode)
    return patch_ins_hex


def calc_md5(file):
    return hashlib.md5(open(file,'rb').read()).hexdigest()
