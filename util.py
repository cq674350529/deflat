#!/usr/bin/env python3

ARCH_X86 = {"X86", "AMD64"}
ARCH_ARM = {"ARMEL", "ARMHF"}

OPCODES = {
    'x86':
        {
            'a': b'\x87', 'ae': b'\x83', 'b': b'\x82', 'be': b'\x86', 'c': b'\x82', 'e': b'\x84', 'z': b'\x84', 'g': b'\x8F', 'ge': b'\x8D', 'l': b'\x8C', 'le': b'\x8E', 'na': b'\x86', 'nae': b'\x82', 'nb': b'\x83', 'nbe': b'\x87', 'nc': b'\x83', 'ne': b'\x85', 'ng': b'\x8E', 'nge': b'\x8C', 'nl': b'\x8D', 'nle': b'\x8F', 'no': 'b\x81', 'np': b'\x8B', 'ns': b'\x89', 'nz': b'\x85', 'o': b'\x80', 'p': b'\x8A', 'pe': b'\x8A', 'po': b'\x8B', 's': b'\x88', 'nop': b'\x90', 'jmp': b'\xE9', 'j': b'\x0F'
         },
    'arm':
        {
            'nop': b'\x00\xF0\x20\xE3', 'b': b'\xEA', 'blt': b'\xBA', 'beq': b'\x0A', 'bne': b'\x1A', 'bgt': b'\xCA', 'bhi': b'\x8A', 'bls': b'\x9A', 'ble': b'\xDA', 'bge': b'\xAA'
        }
}


def fill_nop(data, start_addr, length, arch):
    if arch.name in ARCH_X86:
        for i in range(0, length):
            data[start_addr + i] = ord(OPCODES['x86']['nop'])
    elif arch.name in ARCH_ARM:
        nop_value = OPCODES['arm']['nop']
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
