#!/usr/bin/env python3

import sys
sys.path.append("..")

import angr
import pyvex
import claripy
import struct
from collections import defaultdict

import am_graph

import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
# logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
    
def get_relevant_nop_nodes(supergraph):
    global pre_dispatcher_node, prologue_node, retn_node
    # relevant_nodes = list(supergraph.predecessors(pre_dispatcher_node))
    relevant_nodes = []
    nop_nodes = []
    for node in supergraph.nodes():
        if supergraph.has_edge(node, pre_dispatcher_node) and node.size > 8:
            # XXX: use node.size is faster than to create a block 
            relevant_nodes.append(node)
            continue
        if node.addr in ( prologue_node.addr, retn_node.addr, pre_dispatcher_node.addr):
            continue
        nop_nodes.append(node)
    return relevant_nodes, nop_nodes


def symbolic_execution(start_addr, hook_addr=None, modify=None, inspect=False):
    
    def retn_procedure(state):
        global project
        ip = state.se.eval(state.regs.ip)
        project.unhook(ip)
        return
    
    def statement_inspect(state):
        global modify_value
        expressions = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    global project, relevant_block_addrs, modify_value
    if hook_addr != None:
        project.hook(hook_addr, retn_procedure, length=5)
    if modify != None:
        modify_value = modify
    state = project.factory.blank_state(addr=start_addr, remove_options={angr.sim_options.LAZY_SOLVES})
    if inspect:
        state.inspect.b('statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    sm = project.factory.simulation_manager(state)
    sm.step()
    while len(sm.active) > 0:
        for active_state in sm.active:
            if active_state.addr in relevant_block_addrs:
                return active_state.addr
        sm.step()

def fill_nop(data, start_addr, length):
    global opcode
    for i in range(0, length):
        data[start_addr + i] = ord(opcode['nop'])

def fill_jmp_offset(data, start, offset):
    jmp_offset = struct.pack('<i', offset)  # bytes
    for i in range(4):
        data[start + i] = jmp_offset[i]
    
def patch_byte(data, offset, value):
    # operate on bytearray, not str
    data[offset] = ord(value)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python deflat.py filename function_address(hex)')
        exit(0)
    
    opcode = {'a':'\x87', 'ae': '\x83', 'b':'\x82', 'be':'\x86', 'c':'\x82', 'e':'\x84', 'z':'\x84', 'g':'\x8F', 
              'ge':'\x8D', 'l':'\x8C', 'le':'\x8E', 'na':'\x86', 'nae':'\x82', 'nb':'\x83', 'nbe':'\x87', 'nc':'\x83',
              'ne':'\x85', 'ng':'\x8E', 'nge':'\x8C', 'nl':'\x8D', 'nle':'\x8F', 'no':'\x81', 'np':'\x8B', 'ns':'\x89',
              'nz':'\x85', 'o':'\x80', 'p':'\x8A', 'pe':'\x8A', 'po':'\x8B', 's':'\x88', 'nop':'\x90', 'jmp':'\xE9', 'j':'\x0F'}
    
    filename = sys.argv[1]
    start = int(sys.argv[2], 16)

    project = angr.Project(filename, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast(normalize=True)  # do normalize to avoid overlapping blocks
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
    
    relevant_nodes, nop_nodes = get_relevant_nop_nodes(supergraph)
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
    modify_value = None
    patch_instrs = {}
    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant.addr)
        block = project.factory.block(relevant.addr, size=relevant.size)
        has_branches = False
        hook_addr = None
        for ins in block.capstone.insns:
            if ins.insn.mnemonic.startswith('cmov'):
                patch_instrs[relevant] = ins
                has_branches = True
            elif ins.insn.mnemonic.startswith('call'):
                hook_addr = ins.insn.address
        if has_branches:
            flow[relevant].append(symbolic_execution(relevant.addr, hook_addr, claripy.BVV(1, 1), True))
            flow[relevant].append(symbolic_execution(relevant.addr, hook_addr, claripy.BVV(0, 1), True))
        else:
            flow[relevant].append(symbolic_execution(relevant.addr, hook_addr))
            
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
        fill_nop(origin_data, nop_node.addr - base_addr, nop_node.size)
    
    # remove unnecessary control flows
    for parent, childs in flow.items():
        if len(childs) == 1:
            parent_block = project.factory.block(parent.addr, size=parent.size)
            last_instr = parent_block.capstone.insns[-1]
            file_offset = last_instr.address - base_addr
            # patch the last jmp instruction
            patch_byte(origin_data, file_offset, opcode['jmp'])
            file_offset += 1
            fill_nop(origin_data, file_offset, last_instr.size - 1)
            fill_jmp_offset(origin_data, file_offset, childs[0] - last_instr.address - 5)
        else:
            instr = patch_instrs[parent]
            file_offset = instr.address - base_addr
            # patch instructions starting from `cmovx` to the end of block
            fill_nop(origin_data, file_offset, parent.addr + parent.size - base_addr - file_offset)
            patch_byte(origin_data, file_offset, opcode['j'])
            patch_byte(origin_data, file_offset + 1, opcode[instr.mnemonic[4:]])
            fill_jmp_offset(origin_data, file_offset + 2, childs[0] - instr.address - 6)
            file_offset += 6
            patch_byte(origin_data, file_offset, opcode['jmp'])
            fill_jmp_offset(origin_data, file_offset + 1, childs[1] - (instr.address + 6) - 5)
    
    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % recovery_file)