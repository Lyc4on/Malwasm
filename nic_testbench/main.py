#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Usage: python3 main.py -f wasmwat_samples/bb.wasm -o out.txt

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

    features = parser.add_argument_group('Features')
    features.add_argument('-d', '--decode',
                        action='store_true', help='decode .wasm to wat-like format')

    features.add_argument('-a', '--analyse',
                          action='store_true',
                          help='print Functions instructions analytics')

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
        # print(bytecode_cfg)
        with open(args.output, 'w') as out_file:
            for func in bytecode_cfg.functions:

                # python3 main.py -f wasmwat_samples/cryptonight/cryptonight.wasm -a -o cryptonight_analyse_out.txt
                if args.analyse:
                    out_file.write(str(func))

                # python3 main.py -f wasmwat_samples/cryptonight/cryptonight.wasm -d -o cryptonight_decode_out.txt
                if args.decode:
                    # # octopus.core.function object
                    out_file.write(str(func.prefered_name) + "\n")

                    # octopus.core.instruction object
                    for inst in func.instructions:
                        out_file.write(str(inst) + "\n")
                    
                    out_file.write("\n\n")
            
        out_file.close()
            

if __name__ == '__main__':
    main()
