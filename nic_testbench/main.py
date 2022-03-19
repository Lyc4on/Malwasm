#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Usage: python3 main.py -f bb.wasm -o out.txt

import argparse
import sys

from octopus.arch.wasm.cfg import WasmCFG
from binascii import unhexlify, hexlify
from logging import getLogger
logging = getLogger(__name__)

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Malwasm - WebAssembly Scanner for potential malware')

    inputs = parser.add_argument_group('IO arguments')
    inputs.add_argument('-f', '--file',
                        type=argparse.FileType('rb'),
                        help='binary file (.wasm)',
                        metavar='WASMMODULE')

    inputs.add_argument('-o', '--output',
                        help="-o <file.ext>")

    # features = parser.add_argument_group('Features')
    # features.add_argument('-a', '--analyse',
    #                       action='store_true',
    #                       help='print Functions instructions analytics')

    args = parser.parse_args()

    bytecode = None

    # process input code
    if args.file:
        # bytecode = args.file.read()
        # data = str(bytecode_to_bytes(bytecode))
        # # data = hexlify(data).decode("ascii")
        # output_file(args.output, data)
        input_bytecode = args.file.read()
        bytecode_cfg = WasmCFG(input_bytecode)
        # print(bytecode_cfg.functions)
        with open(args.output, 'w') as out_file:
            for func in bytecode_cfg.functions:
                out_file.write(str(func))
            
        out_file.close()
            

if __name__ == '__main__':
    main()
