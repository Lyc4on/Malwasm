#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Usage: python3 wasmanalyzer.py -d -f wasmwat_samples/bb.wasm -o out.txt

import argparse
import sys

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
                        help='binary file (.wasm)',
                        metavar='WASMMODULE')

    inputs.add_argument('-o', '--output',
                        help="-o <file.ext>")

    features = parser.add_argument_group('Features')
    features.add_argument('-d', '--disassmble',
                        action='store_true', help='disassmble .wasm to wat-like format')

    features.add_argument('-a', '--analyse',
                          action='store_true',
                          help='print Functions instructions analytics')

    args = parser.parse_args()

    in_raw = None
    outfile = None

    # process input code
    if args.file:
        # Read file
        with open(args.file, 'rb') as raw:
            raw = raw.read()

        # Open output file
        if args.output:
            outfile = open(args.output, 'w')

        mod_iter = iter(decode_module(raw, decode_name_subsections=True))
        hdr, hdr_data = next(mod_iter)
        
        code_sec = None
        type_sec = None
        func_sec = None

        for cur_sec, cur_sec_data in mod_iter:
            # outfile.write('Writing current section:\n')
            # outfile.write(cur_sec.to_string(cur_sec_data) + '\n')
            if type(cur_sec) == Section:
                if cur_sec_data.id == SEC_CODE:
                    # outfile.write('Current section is SEC_CODE\n')
                    code_sec = cur_sec_data.payload
                elif cur_sec_data.id == SEC_TYPE:
                    # outfile.write('Current section is SEC_TYPE\n')
                    type_sec = cur_sec_data.payload
                elif cur_sec_data.id == SEC_FUNCTION:
                    # outfile.write('Current section is SEC_FUNCTION\n')
                    func_sec = cur_sec_data.payload
            # outfile.write('\n')
        
        mod_obj = classes.Module() # Module Object

        # Disassemble
        if args.disassmble and code_sec is not None:
            for i, func_body in enumerate(code_sec.bodies):
                outfile.write('{x} sub_{id:04X} {x}\n'.format(x='=' * 35, id=i))

                # If we have type info, use it.
                func_type = type_sec.entries[func_sec.types[i]] if (
                    None not in (type_sec, func_sec)
                ) else None

                outfile.write('\n')
                outfile.write('\n'.join(format_function(func_body, func_type)))
                outfile.write('\n')

                func_obj = classes.Function(i, func_body, func_type) # Create Function object
                mod_obj.add_func(func_obj) # Add Function obj to module object

        print(mod_obj)

        outfile.close()            

if __name__ == '__main__':
    main()
