#!/usr/bin/env python3

import sys
sys.path.append("..")

import struct
import angr

import am_graph

import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
# logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

opcodes = {'nop': '\x90', 'jmp': '\xE9'}

def fill_nop(data, start_addr, length):
    for i in range(0, length):
        data[start_addr + i] = ord(opcodes['nop'])

def fill_jmp_offset(data, start, offset):
    jmp_offset = struct.pack('<i', offset)
    for i in range(4):
        data[start + i] = jmp_offset[i]
    
def patch_byte(data, offset, value):
    # operate on bytearray, not str
    data[offset] = ord(value)

def main():
    if len(sys.argv) != 3:
        print('Usage: python debougs.py filename function_address(hex)')
        exit(0)
    
    filename = sys.argv[1]
    start = int(sys.argv[2], 16)

    project = angr.Project(filename, load_options={'auto_load_libs':False})
    cfg = project.analyses.CFGFast(normalize=True)
    target_function = cfg.functions.get(start)
    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    state = project.factory.blank_state(addr=target_function.addr, remove_options={angr.sim_options.LAZY_SOLVES})

    flow = set()
    flow.add(target_function.addr)

    print('*******************symbolic execution*********************')
    sm = project.factory.simulation_manager(state)
    sm.step()
    while len(sm.active) > 0:
        for active in sm.active:
            flow.add(active.addr)
        sm.step()
    
    print('executed blocks: ', list(map(hex, flow)))
    
    print('************************patch******************************')

    with open(filename, 'rb') as origin:
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)

    patch_nodes = set()
    for node in supergraph.nodes():
        if node.addr in patch_nodes:
            continue

        if node.addr not in flow:
            # patch unnecessary node
            file_offset = node.addr - base_addr
            fill_nop(origin_data, file_offset, node.size)
        else:
            suc_nodes = list(supergraph.successors(node))
            jmp_targets = []
            
            for suc_node in suc_nodes:
                if suc_node.addr in flow:
                    jmp_targets.append(suc_node.addr)
                else:
                    # patch unnecessary suc_node
                    file_offset = suc_node.addr - base_addr
                    fill_nop(origin_data, file_offset, suc_node.size)
                    patch_nodes.add(suc_node.addr)
            
            # patch jmp instruction
            if len(suc_nodes) > 1 and len(jmp_targets) == 1:
                file_offset = node.addr + node.size - 6 - base_addr
                patch_byte(origin_data, file_offset, opcodes['nop'])
                patch_byte(origin_data, file_offset+1, opcodes['jmp'])
                fill_jmp_offset(origin_data, file_offset+2, jmp_targets[0]- (node.addr + node.size))

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"

    recovery_file = filename + '_recovered'
    with open(recovery_file, 'wb') as recovery:
       recovery.write(origin_data)
    
    print('Successful! The recovered file: %s' % recovery_file)
        

if __name__ == "__main__":
    main()