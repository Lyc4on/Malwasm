#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Usage:
# python3 wasmanalyzer.py -d -f nic_testbench/wasmwat_samples/cryptonight/cryptonight.wasm

import argparse, sys, os, json
from operator import mod
import graphviz
from classes import classes
from wasm import (
    decode_module, decode_bytecode,
    format_instruction, format_lang_type, 
    format_mutability, format_function,
    SEC_DATA, SEC_ELEMENT, SEC_GLOBAL,
    SEC_CODE, SEC_TYPE, SEC_FUNCTION, Section,
    INSN_ENTER_BLOCK,
    INSN_LEAVE_BLOCK,)

from logging import getLogger
logging = getLogger(__name__)

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Malwasm - WebAssembly Scanner for potential malware')

    inputs = parser.add_argument_group('IO arguments')
    inputs.add_argument('-f', '--file',
                        help='binary file (.wasm)')
    
    inputs.add_argument('-r', '--rule', 
                        help='rule file (.json)')

    features = parser.add_argument_group('Features')
    features.add_argument('-d', '--disassmble',
                        action='store_true', 
                        help='disassmble .wasm to wat-like format')

    features.add_argument('-a', '--analyse',
                          action='store_true',
                          help='print Functions instructions analytics')
                        
    features.add_argument('-gr', '--genRule',
                          action='store_true',
                          help='generate JSON rule')

    args = parser.parse_args()

    # Global Variables
    mod_obj = classes.Module() # Module Object for -d, -a, -gr
    rule_obj = classes.Rule() # for -r

    # Process Rule
    if args.rule:
        with open(args.rule) as rule_raw:
            rule_json = json.load(rule_raw)
            rule_obj.load_json(rule_json)
            # print(rule_json)
    # print(rule_obj)

    # Process input code
    if args.file:
        # Read file
        with open(args.file, 'rb') as raw:
            raw_read = raw.read()
            raw.close()
            
        mod_iter = iter(decode_module(raw_read, decode_name_subsections=True))
        
        code_sec = None
        type_sec = None
        func_sec = None

        for cur_sec, cur_sec_data in mod_iter:
            if type(cur_sec) == Section:
                if cur_sec_data.id == SEC_CODE:
                    code_sec = cur_sec_data.payload
                elif cur_sec_data.id == SEC_TYPE:
                    type_sec = cur_sec_data.payload
                elif cur_sec_data.id == SEC_FUNCTION:
                    func_sec = cur_sec_data.payload
        
        # Disassemble
        if (args.genRule or args.disassmble) and code_sec is not None:
            for i, func_body in enumerate(code_sec.bodies):
                # If we have type info, use it.
                func_type = type_sec.entries[func_sec.types[i]] if (
                    None not in (type_sec, func_sec)
                ) else None

                func_obj = classes.Function(i, func_body, func_type) # Create Function object
                mod_obj.add_func(func_obj) # Add Function obj to module object
        
        mod_obj.profile_module()
        mod_obj.analyse_cfg()

        # Save disassemble analysis results
        of_str_w = of_str_t = args.file.split(os.sep)[-1] # Get the ../../<of_str.wasm>
        of_str_w = of_str_w.split('.')[0] + '_dis.wat'
        of_str_t = of_str_t.split('.')[0] + '_dis.txt'
        of_path_w = os.getcwd() + os.sep + of_str_w
        of_path_t = os.getcwd() + os.sep + of_str_t

        mod_of_w = open(of_path_w, 'w')
        mod_of_w.write(mod_obj.get_wat())
        mod_of_w.close()

        mod_of_t = open(of_path_t, 'w')
        mod_of_t.write(str(mod_obj))
        mod_of_t.close()

        # Save json rule
        if args.genRule:
            tmp_name = of_str = args.file.split(os.sep)[-1] # Get the ../../<of_str.wasm>
            of_str = of_str.split('.')[0] + '_rule.json'
            of_path = os.getcwd() + os.sep + of_str
            with open(of_path, "w") as write_file:
                json_to_write = mod_obj.export_rule(tmp_name)
                json.dump(json_to_write, write_file, indent=2)
                write_file.close()

        # Implement CFG function


if __name__ == '__main__':
    main()
