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

    # Process input code
    if args.file:
        # Read file
        with open(args.file, 'rb') as raw:
            raw_read = raw.read()
            raw.close()
            
        mod_iter = iter(decode_module(raw_read, decode_name_subsections=True))
        
        # Disassemble OR Generate JSON Rule
        if args.genRule or args.disassmble:
            mod_obj.disassemble(mod_iter) # disassemble    
            mod_obj.profile_module() # 
            mod_obj.analyse_cfg()

            # Export disassemble results
            mod_obj.export_dis_txt(args.file) # Write out Module information
            mod_obj.export_dis_wat(args.file) # Write out Module pseudo wat

        # Save json rule
        if args.genRule:
            mod_obj.export_rule_json(args.file)

        # Implement CFG function


if __name__ == '__main__':
    main()
