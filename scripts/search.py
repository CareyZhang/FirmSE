#!/usr/bin/env python3
import r2pipe
import json
import re
import sys
import angr
import claripy
from angr import SimProcedure

base = 0x400000
device_open_match_space_arm = 0x20
device_open_match_space_mips = 0x20
open_ioctl_match_space_arm = 0x200
open_ioctl_match_space_mips = 0x400
trace_range = 0x30
arg_type = 0
arg_offset = 0
cmd_value = 0
arg_value = 0
return_value = 0

def find_func_offset(r, func_name):
    # Method 1
    name = 'sym.imp.{}'.format(func_name)
    offset = r.cmd('afo ' + name)
    
    if offset == '':
        # Method 2
        offset = r.cmd('afo {}'.format(func_name))

    if offset == '':
        # Method 3
        r.cmd('s ' + name)
        offset = r.cmd('s')

    if offset != '':
        func_offset = int(offset, 16)
        return func_offset
    else:
        return -1

def find_func_ref(r, func_offset):
    func_ref = r.cmd('axtj {}'.format(func_offset))
    func_ref_json = json.loads(func_ref)

    func_calling_addrs = []

    for item in func_ref_json:
        if item['type'].lower() == 'call':
            func_calling_addrs.append(int(hex(item['from']),16))
            
    if len(func_calling_addrs) == 0:
        return -1

    return func_calling_addrs

def static_analysis(file_name,device_name):
    try:
        r = r2pipe.open(file_name)
    except:
        print("Can't open file")

    # Analysis
    r.cmd('aaa')
    r.cmd('aae')
    r.cmd('aaf')

    # Get Architecture
    archjson = json.loads(r.cmd('iAj'))
    arch_name = archjson['bins'][0]['arch']
    arch_bits = archjson['bins'][0]['bits']

    # is PIE?
    filejson = json.loads(r.cmd('ij'))
    if 'EXEC' in filejson['core']['type']:
        PIE = False
    else:
        PIE = True

    # Find device name reference
    device_result = r.cmd('/j /dev/{}'.format(device_name))
    device_result_json = json.loads(device_result)
    device_addr = 0
    for item in device_result_json:
        if '/dev/{}'.format(device_name) in item['data']:
            device_addr = item['offset']
    if device_addr == 0:
        print("[*] device address not found!")

    device_ref = r.cmd('axtj {}'.format(device_addr))
    device_ref_json = json.loads(device_ref)
    device_ref = []
    for item in device_ref_json:
        if item['type'] == 'DATA':
            device_ref.append(item['from'])
    if len(device_ref) == 0:
        print("[*] device address not found!")
        exit(1)

    # Find ioctl reference
    open_offset = find_func_offset(r, 'open')
    if open_offset == -1:
        print("[*] open offset not found!")
        exit(1)

    open_ref = find_func_ref(r, open_offset)
    if open_ref == -1:
        print("[*] open reference not found!")
        exit(1)

    # Find ioctl reference
    ioctl_offset = find_func_offset(r, 'ioctl')
    if ioctl_offset == -1:
        print("[*] ioctl offset not found!")
        exit(1)

    ioctl_ref = find_func_ref(r, ioctl_offset)
    if ioctl_ref == -1:
        print("[*] ioctl reference not found!")
        exit(1)
    
    # Find perror reference
    perror_offset = find_func_offset(r, 'perror')
    if perror_offset == -1:
        print("[*] perror offset not found!")
    
    perror_ref = find_func_ref(r, perror_offset)
    if perror_ref == -1:
        print("[*] perror reference not found!")

    # Find perror reference
    close_offset = find_func_offset(r, 'close')
    if close_offset == -1:
        print("[*] close offset not found!")
        exit(1)
    
    close_ref = find_func_ref(r, close_offset)
    if close_ref == -1:
        print("[*] close reference not found!")
        exit(1)

    candidates = []
    if arch_name == 'arm':
        for device_ref_adr in device_ref:
            for open_ref_adr in open_ref:
                for ioctl_ref_adr in ioctl_ref:
                    if device_ref_adr <= open_ref_adr and (open_ref_adr - device_ref_adr) <= device_open_match_space_arm:
                        if open_ref_adr < ioctl_ref_adr and (ioctl_ref_adr - open_ref_adr) <= open_ioctl_match_space_arm:
                            candidates.append((open_ref_adr,ioctl_ref_adr))
    elif arch_name == 'mips':
        for device_ref_adr in device_ref:
            for open_ref_adr in open_ref:
                for ioctl_ref_adr in ioctl_ref:
                    # if device_ref_adr <= open_ref_adr and (open_ref_adr - device_ref_adr) <= device_open_match_space_mips:
                    if open_ref_adr < ioctl_ref_adr and (ioctl_ref_adr - open_ref_adr) <= open_ioctl_match_space_mips:
                        print(device_ref_adr,open_ref_adr,ioctl_ref_adr)
                        candidates.append((open_ref_adr,ioctl_ref_adr))

    if len(candidates) == 0:
        print("[*] rule candidate not found!")
        exit(1)
    else:
        return candidates, perror_ref, close_ref, arch_name, arch_bits, PIE

def run_symbolic(project, file_name, candidate_list, avoid_list, sink_list, arch_name, arch_bits, PIE):
    if arch_name == 'arm':
        if arch_bits == 32:
            return run_symbolic_arm(project, file_name, candidate_list, avoid_list, sink_list, PIE)
    elif arch_name == 'mips':
        if arch_bits == 32:
            return run_symbolic_mips(project, file_name, candidate_list, avoid_list, sink_list, PIE)

    print('The architecture "{}_{}" isn\'t supported.'.format(arch_name, arch_bits))
    exit(1)

def run_symbolic_arm(project, file_name, candidate_list, avoid_list, sink_list, PIE):
    global arg_type, arg_offset, arg_value, return_value
    r = r2pipe.open(file_name)
    arg_size_in_bits = 32
    ret_size_in_bits = 32 

    def hook_arm_cmd(state):
        global cmd_value
        cmd_value = hex(state.solver.eval(state.regs.r1))
        # print("cmd hook pc:",hex(state.solver.eval(state.regs.pc)))
    
    def hook_arm_arg(state):
        global arg_type, arg_offset, arg_value
        if arg_type == 1:
            fake_sp_addr = 0xffffc94c
            state.regs.sp = fake_sp_addr
            state.memory.store(fake_sp_addr + arg_offset, arg_value, endness=project.arch.memory_endness)
        if arg_type == 2:
            fake_r11_addr = 0xffffc94c
            state.regs.r11 = fake_r11_addr
            state.memory.store(fake_r11_addr - arg_offset, arg_value, endness=project.arch.memory_endness)
        # print("arg hook pc:",hex(state.solver.eval(state.regs.pc)))

    def hook_arm_ret(state):
        global return_value
        state.regs.r0 = return_value
        # print("ret hook pc:",hex(state.solver.eval(state.regs.pc)))

    if PIE == True:
        open_ref_list = [i[0] for i in candidate_list]
        ioctl_ref_list = [i[1] for i in candidate_list]
        avoid_list = [i+base for i in avoid_list]
        sink_list = [i+base for i in sink_list]
    else:
        open_ref_list = [i[0] for i in candidate_list]
        ioctl_ref_list = [i[1] for i in candidate_list]
        avoid_list = [i for i in avoid_list]
        sink_list = [i for i in sink_list]

    rules = []
    for ioctl_ref in ioctl_ref_list:
        global arg_type, arg_offset, arg_value, return_value, cmd_value
        trace = 0
        cmd_hook_adr = 0
        arg_hook_adr = 0
        ret_hook_adr = ioctl_ref

        arg_type = 0
        arg_offset = 0
        cmd_value = 0
        arg_value = claripy.BVS('arg_value', arg_size_in_bits)
        return_value = claripy.BVS('return_value', ret_size_in_bits)

        # infer hook cmd address
        for trace in range(0x00,trace_range,0x04):
            trace_opc = json.loads(r.cmd("pdj 1 @ {}".format(hex(ioctl_ref - trace)))[1:-3])["opcode"]
            if "ldr r1" in trace_opc:
                cmd_hook_adr = ioctl_ref - trace + 4
                break
        if cmd_hook_adr == 0:
            continue

        # infer hook arg address offset
        for trace in range(0x00,trace_range,0x04):
            trace_opc = json.loads(r.cmd("pdj 1 @ {}".format(hex(ioctl_ref - trace)))[1:-3])["opcode"]
            if "r2" in trace_opc and "sp" in trace_opc:
                search_offset = re.search("0x[0-9]*", trace_opc)
                if search_offset:
                    arg_type = 1
                    arg_offset = int(search_offset.group(0),16)
                    arg_hook_adr = ioctl_ref + 4
                    break
                else:
                    continue
            if "sub r3, fp" in trace_opc:
                search_offset = re.search("0x[0-9A-F]*", trace_opc)
                if search_offset:
                    arg_type = 2
                    arg_offset = int(search_offset.group(0),16)
                    arg_hook_adr = ioctl_ref + 4
                    break
                else:
                    continue

        initial_state = project.factory.blank_state(addr=cmd_hook_adr - 4)
        simulation = project.factory.simgr(initial_state)
        if arg_type != 0:
            project.hook(addr=cmd_hook_adr, hook=hook_arm_cmd, length=ret_hook_adr - cmd_hook_adr)
            project.hook(addr=ret_hook_adr, hook=hook_arm_ret, length=4)
            project.hook(addr=arg_hook_adr, hook=hook_arm_arg, length=0)
        else:
            project.hook(addr=cmd_hook_adr, hook=hook_arm_cmd, length=ret_hook_adr-cmd_hook_adr)
            project.hook(addr=ret_hook_adr, hook=hook_arm_ret, length=0)

        simulation.explore(find=sink_list, avoid=avoid_list)
        if simulation.found:
            for i in simulation.found:
                solution_state = i
                rules.append((cmd_value,format(solution_state.solver.eval(arg_value),'x'),format(solution_state.solver.eval(return_value),'x')))
    return rules

def run_symbolic_mips(project, file_name, candidate_list, avoid_list, sink_list, PIE):
    global arg_type, arg_offset, arg_value, return_value
    r = r2pipe.open(file_name)
    arg_size_in_bits = 32
    ret_size_in_bits = 32

    def hook_mips_cmd(state):
        global cmd_value
        cmd_value = hex(state.solver.eval(state.regs.a1))
    
    def hook_mips_arg(state):
        global arg_type, arg_offset, arg_value
        if arg_type == 1:
            fake_fp_addr = 0xffffc94c
            state.regs.fp = fake_fp_addr
            state.memory.store(fake_fp_addr + arg_offset, arg_value, endness=project.arch.memory_endness)

    def hook_mips_ret(state):
        global return_value
        state.regs.v0 = return_value

    if PIE == True:
        open_ref_list = [i[0] for i in candidate_list]
        ioctl_ref_list = [i[1] for i in candidate_list]
        avoid_list = [i+base for i in avoid_list]
        sink_list = [i+base for i in sink_list]
    else:
        open_ref_list = [i[0] for i in candidate_list]
        ioctl_ref_list = [i[1] for i in candidate_list]
        avoid_list = [i for i in avoid_list]
        sink_list = [i for i in sink_list]

    rules = []
    for ioctl_ref in ioctl_ref_list:
        global arg_type, arg_offset, arg_value, return_value, cmd_value
        trace = 0
        cmd_hook_adr = 0
        arg_hook_adr = 0
        ret_hook_adr = ioctl_ref

        arg_type = 0
        arg_offset = 0
        cmd_value = 0
        arg_value = claripy.BVS('arg_value', arg_size_in_bits)
        return_value = claripy.BVS('return_value', ret_size_in_bits)
        
        # infer hook cmd address
        for trace in range(0x00,trace_range,0x04):
            trace_opc = json.loads(r.cmd("pdj 1 @ {}".format(hex(ioctl_ref - trace)))[1:-3])["opcode"]
            if "a1" in trace_opc:
                cmd_hook_adr = ioctl_ref - trace + 4
                break
        if cmd_hook_adr == 0:
            continue

        # infer hook arg address offset
        for trace in range(0x00,trace_range,0x04):
            trace_opc = json.loads(r.cmd("pdj 1 @ {}".format(hex(ioctl_ref - trace)))[1:-3])["opcode"]
            if "fp" in trace_opc and "fd" not in trace_opc:
                search_offset = re.search("0x[0-9]*", trace_opc)
                if search_offset:
                    arg_type = 1
                    arg_offset = int(search_offset.group(0),16)
                    arg_hook_adr = ioctl_ref + 4
                    break
                else:
                    continue

        initial_state = project.factory.blank_state(addr=cmd_hook_adr - 8)
        simulation = project.factory.simgr(initial_state)

        print("hook addr",hex(cmd_hook_adr),hex(ret_hook_adr),hex(arg_hook_adr))
        if arg_type != 0:
            project.hook(addr=cmd_hook_adr, hook=hook_mips_cmd, length=ret_hook_adr - cmd_hook_adr)
            project.hook(addr=ret_hook_adr, hook=hook_mips_ret, length=4)
            project.hook(addr=arg_hook_adr, hook=hook_mips_arg, length=0)
        else:
            project.hook(addr=cmd_hook_adr, hook=hook_mips_cmd, length=ret_hook_adr-cmd_hook_adr)
            project.hook(addr=ret_hook_adr, hook=hook_mips_ret, length=0)
        
        simulation.explore(find=sink_list, avoid=avoid_list)
        if simulation.found:
            for i in simulation.found:
                solution_state = i
                rules.append((cmd_value,format(solution_state.solver.eval(arg_value),'x'),format(solution_state.solver.eval(return_value),'x')))

    return rules

def main(argv):
    if len(argv) < 3:
        print("[*] please specify the binary name & device name in arg")
        return
    file_name = argv[1]
    device_name = argv[2]
    config_path = argv[3]
    project = angr.Project(file_name)
    candidates, perror_ref, close_ref, arch_name, arch_bits, PIE = static_analysis(file_name, device_name) # candidates = [(open_ref,ioctl_ref)]
    rules = run_symbolic(project, file_name, candidates, perror_ref, close_ref, arch_name, arch_bits, PIE)  # rules = [(cmd,arg,ret)]
    print("\n-------------------------")
    print("[*] Static analysis\n")
    print("device:\t", device_name)
    print("arch_name:\t", arch_name)
    print("arch_bits:\t", arch_bits)
    print("PIE:\t\t", PIE)
    print("open:\t\t", [hex(i[0]) for i in candidates])
    print("ioctl:\t\t", [hex(i[1]) for i in candidates])
    print("perror:\t\t", [hex(i) for i in perror_ref])
    print("close:\t\t", [hex(i) for i in close_ref])
    print("\n-------------------------")
    print("[*]Config generating: " + device_name + '.config')
    print("rules:\t\t", rules)
    with open("{}/{}.config".format(config_path, device_name),"a") as f:
        for rule in rules:
            f.write("{}\t{}\t{}\n".format(rule[0],rule[1],rule[2]))

if __name__ == "__main__":
    main(sys.argv)
