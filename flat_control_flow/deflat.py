#!/usr/bin/env python3

import sys
sys.path.append("..")

import argparse
import angr
import pyvex
import claripy
import struct
from collections import defaultdict

import am_graph
from util import *

import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
# logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
    

def get_relevant_nop_nodes(supergraph, pre_dispatcher_node, prologue_node, retn_node):
    # relevant_nodes = list(supergraph.predecessors(pre_dispatcher_node))
    relevant_nodes = []
    nop_nodes = []
    for node in supergraph.nodes():
        if supergraph.has_edge(node, pre_dispatcher_node) and node.size > 8:
            # XXX: use node.size is faster than to create a block
            relevant_nodes.append(node)
            continue
        if node.addr in (prologue_node.addr, retn_node.addr, pre_dispatcher_node.addr):
            continue
        nop_nodes.append(node)
    return relevant_nodes, nop_nodes


def symbolic_execution(project, relevant_block_addrs, start_addr, hook_addr=None, modify_value=None, inspect=False):

    def retn_procedure(state):
        ip = state.solver.eval(state.regs.ip)
        project.unhook(ip)
        return

    def statement_inspect(state):
        expressions = list(
            state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    if hook_addr != None:
        if project.arch.name in ARCH_X86:
            project.hook(hook_addr, retn_procedure, length=5)
        elif project.arch.name in ARCH_ARM:
            project.hook(hook_addr, retn_procedure, length=4)

    state = project.factory.blank_state(addr=start_addr, remove_options={
                                        angr.sim_options.LAZY_SOLVES})
    if inspect:
        state.inspect.b(
            'statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    sm = project.factory.simulation_manager(state)
    sm.step()
    while len(sm.active) > 0:
        for active_state in sm.active:
            if active_state.addr in relevant_block_addrs:
                return active_state.addr
        sm.step()


def main():
    parser = argparse.ArgumentParser(description="deflat control flow script")
    parser.add_argument("-f", "--file", help="binary to analyze")
    parser.add_argument(
        "--addr", help="address of target function in hex format")
    args = parser.parse_args()

    if args.file is None or args.addr is None:
        parser.print_help()
        sys.exit(0)

    filename = args.file
    start = int(args.addr, 16)

    project = angr.Project(filename, load_options={'auto_load_libs': False})
    # do normalize to avoid overlapping blocks, disable force_complete_scan to avoid possible "wrong" blocks
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    target_function = cfg.functions.get(start)
    # A super transition graph is a graph that looks like IDA Pro's CFG
    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    # get prologue_node and retn_node
    prologue_node = None
    for node in supergraph.nodes():
        if supergraph.in_degree(node) == 0:
            prologue_node = node
        if supergraph.out_degree(node) == 0:
            retn_node = node

    if prologue_node is None or prologue_node.addr != start:
        print("Something must be wrong...")
        sys.exit(-1)

    main_dispatcher_node = list(supergraph.successors(prologue_node))[0]
    for node in supergraph.predecessors(main_dispatcher_node):
        if node.addr != prologue_node.addr:
            pre_dispatcher_node = node
            break

    relevant_nodes, nop_nodes = get_relevant_nop_nodes(
        supergraph, pre_dispatcher_node, prologue_node, retn_node)
    print('*******************relevant blocks************************')
    print('prologue: %#x' % start)
    print('main_dispatcher: %#x' % main_dispatcher_node.addr)
    print('pre_dispatcher: %#x' % pre_dispatcher_node.addr)
    print('retn: %#x' % retn_node.addr)
    relevant_block_addrs = [node.addr for node in relevant_nodes]
    print('relevant_blocks:', [hex(addr) for addr in relevant_block_addrs])

    print('*******************symbolic execution*********************')
    relevants = relevant_nodes
    relevants.append(prologue_node)
    relevants_without_retn = list(relevants)
    relevants.append(retn_node)
    relevant_block_addrs.extend([prologue_node.addr, retn_node.addr])

    flow = defaultdict(list)
    patch_instrs = {}
    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant.addr)
        block = project.factory.block(relevant.addr, size=relevant.size)
        has_branches = False
        hook_addr = None
        for ins in block.capstone.insns:
            if project.arch.name in ARCH_X86:
                if ins.insn.mnemonic.startswith('cmov'):
                    patch_instrs[relevant] = ins
                    has_branches = True
                elif ins.insn.mnemonic.startswith('call'):
                    hook_addr = ins.insn.address
            elif project.arch.name in ARCH_ARM:
                if ins.insn.mnemonic != 'mov' and ins.insn.mnemonic.startswith('mov'):
                    patch_instrs[relevant] = ins
                    has_branches = True
                elif ins.insn.mnemonic in {'bl', 'blx'}:
                    hook_addr = ins.insn.address
        if has_branches:
            flow[relevant].append(symbolic_execution(project, relevant_block_addrs,
                                                     relevant.addr, hook_addr, claripy.BVV(1, 1), True))
            flow[relevant].append(symbolic_execution(project, relevant_block_addrs,
                                                     relevant.addr, hook_addr, claripy.BVV(0, 1), True))
        else:
            flow[relevant].append(symbolic_execution(
                project, relevant_block_addrs, relevant.addr, hook_addr))

    print('************************flow******************************')
    for k, v in flow.items():
        print('%#x: ' % k.addr, [hex(child) for child in v])

    # print retn_node flow. Actually, it's [].
    print('%#x: ' % retn_node.addr, [])

    print('************************patch*****************************')
    with open(filename, 'rb') as origin:
        # Attention: can't transform to str by calling decode() directly. so use bytearray instead.
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)

    recovery_file = filename + '_recovered'
    recovery = open(recovery_file, 'wb')

    # patch irrelevant blocks
    for nop_node in nop_nodes:
        fill_nop(origin_data, nop_node.addr-base_addr,
                 nop_node.size, project.arch)

    # remove unnecessary control flows
    for parent, childs in flow.items():
        if len(childs) == 1:
            parent_block = project.factory.block(parent.addr, size=parent.size)
            last_instr = parent_block.capstone.insns[-1]
            file_offset = last_instr.address - base_addr
            # patch the last instruction to jmp
            if project.arch.name in ARCH_X86:
                fill_nop(origin_data, file_offset,
                         last_instr.size, project.arch)
                jmp_opcode = OPCODES['x86']['jmp']
                jmp_offset = childs[0] - last_instr.address - 5
                patch_value = jmp_opcode+struct.pack('<i', jmp_offset)
            elif project.arch.name in ARCH_ARM:
                b_opcode = OPCODES['arm']['b']
                b_offset = (childs[0] - last_instr.address - 4*2) // 4
                patch_value = struct.pack('<i', b_offset)[:-1]+b_opcode
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            patch_instruction(origin_data, file_offset, patch_value)
        else:
            instr = patch_instrs[parent]
            file_offset = instr.address - base_addr
            # patch instructions starting from `cmovx` to the end of block
            fill_nop(origin_data, file_offset, parent.addr +
                     parent.size - base_addr - file_offset, project.arch)
            if project.arch.name in ARCH_X86:
                # patch the cmovx instruction to jx instruction
                jmpx_opcode = OPCODES['x86']['j'] + \
                    OPCODES['x86'][instr.mnemonic[len('cmov'):]]
                jmpx_offset = childs[0] - instr.address - 6
                patch_value = jmpx_opcode + struct.pack('<i', jmpx_offset)
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 6
                # patch the next instruction to jmp instrcution
                jmp_opcode = OPCODES['x86']['jmp']
                jmp_offset = childs[1] - (instr.address + 6) - 5
                patch_value = jmp_opcode + struct.pack('<i', jmp_offset)
                patch_instruction(origin_data, file_offset, patch_value)
            elif project.arch.name in ARCH_ARM:
                # patch the movx instruction to bx instruction
                bx_opcode = OPCODES['arm']['b'+instr.mnemonic[len('mov'):]]
                bx_offset = (childs[0] - instr.address - 4*2) // 4
                patch_value = struct.pack('<i', bx_offset)[:-1] + bx_opcode
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 4
                # patch the next instruction to b instrcution
                b_opcode = OPCODES['arm']['b']
                b_offset = (childs[1] - (instr.address + 4) - 4*2) // 4
                patch_value = struct.pack('<i', b_offset)[:-1] + b_opcode
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % recovery_file)


if __name__ == '__main__':
    main()
