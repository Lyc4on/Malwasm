#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Usage:
# python3 wasmanalyzer.py -d -f nic_testbench/wasmwat_samples/cryptonight/cryptonight.wasm 
import argparse, sys, os, json, subprocess, time, glob, yara, pyfiglet, urllib
from graphviz import render
from pathlib import Path
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from classes import classes
from wasm import (
    decode_module, decode_bytecode,
    format_instruction, format_lang_type, 
    format_mutability, format_function,
    SEC_DATA, SEC_ELEMENT, SEC_GLOBAL,
    SEC_CODE, SEC_TYPE, SEC_FUNCTION, Section,
    INSN_ENTER_BLOCK,
    INSN_LEAVE_BLOCK,)

import logging
log = logging.getLogger("Malwasm")

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Malwasm - WebAssembly Scanner for potential malware')

    inputs = parser.add_argument_group('IO arguments')
    inputs.add_argument('-f', '--file',
                        help='binary file (.wasm)')
    
    inputs.add_argument('-r', '--rule',
                        help='rule file (.json)')

    inputs.add_argument('-fn', '--func',
                        help='function name for CFG & DFG')
    
    inputs.add_argument("-u", "--URL", default=None, help="URL of website")

    features = parser.add_argument_group('Features')
    features.add_argument('-d', '--disassemble',
                        action='store_true', 
                        help='disassemble .wasm to wat-like format')

    features.add_argument('-a', '--analyse', nargs='?', default=None, const='1',
                          help='[ANALYSE] : 1 - surface, 2 - deep | -a [1,2] -f <wasm> module against -r <rule.json>')
                        
    features.add_argument('-gr', '--genRule',
                          action='store_true',
                          help='generate JSON rule')
    
    features.add_argument('-y', '--yara-rules',
                            action='store_true',    
                          help='enter yara rules file directory path')
    
    features.add_argument('-cg', '--gen-callgraph',
                          action='store_true',
                          help='generate callgraph')
    
    features.add_argument('-cfg', '--gen-control-flow-graph',
                            action='store_true',
                          help='generate control-flow-graph with specified function name')
    
    features.add_argument('-dfg', '--gen-data-flow-graph',
                            action='store_true',    
                          help='generate data-flow-graph with specified function name')

    args = parser.parse_args()

    # Global Variables
    mod_obj = classes.Module() # Module Object for -d, -a, -gr
    rule_obj = classes.Rule() # Rule Object for -r
    an_obj = classes.Analysis() # Analysis Object for -a

    # Create banner
    ascii_banner = pyfiglet.figlet_format("Malwasm")
    print(ascii_banner)
    
    # URL input
    if args.URL:
        # Check to ensure input is a valid URL
        if args.URL.startswith('http://') or args.URL.startswith('https://'):
            pass
        else:
            raise ValueError("Please enter a valid URL!")
        # Create Temp folder if it does not exist
        Path("Temp").mkdir(parents=True, exist_ok=True)

        # Disable logging in WebDriverManager
        os.environ['WDM_LOG'] = '0'

        # Set Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        ser = Service(ChromeDriverManager().install())

        # Get absolute path to Temp directory
        working_directory = os.getcwd() + os.sep + "Temp" + os.sep
        wasm_arr = []

        print("[+] Detecting WASM files in " + args.URL)
        # Create webdriver instance with specified options
        driver = webdriver.Chrome(service=ser, options=chrome_options)
        # Navigate to the specified URL
        driver.get(args.URL)
        # Wait for 5 seconds for the network requests to be made
        time.sleep(5)

        # Access requests via the 'requests' attribute
        for request in driver.requests:
            if request.response and request.response.headers['Content-Type'] == 'application/wasm':
                wasm_arr.append(request.url)
                filename = os.path.basename(request.url)
                full_filename = os.path.join(working_directory, filename)
                # Save the .wasm file into Temp folder
                urllib.request.urlretrieve(request.url, filename=full_filename)
                break

        # Close all windows and end driver's process
        driver.quit()

        print("[+] Detection Results: ")
        # Print out all WASM files that were detected
        if len(wasm_arr) == 0:
            print("    No WASM files detected!")
        else:
            print("    Number of WASM files detected: " + str(len(wasm_arr)))
            print("    WASM files detected:")
            for wasm_file in wasm_arr:
                print("    - " + wasm_file + ':')
                try:
        	        retrievedFile = open(working_directory + wasm_file.split('/')[-1], 'rb')
                except IOError:
                    print(wasm_file.split('/')[-1] + "file not found!\n Exiting")
                    sys.exit(0)
                fileHead = retrievedFile.read(4)
                if(fileHead.startswith(bytes([0x00, 0x61, 0x73, 0x6D]))):
                    print('File ' + wasm_file.split('/')[-1] + ' magic matches Web Assembly Binary Format')
                else:
                    print('File ' + wasm_file.split('/')[-1] + ' magic does not match Web Assembly Binary Format')

    # Process input code
    if args.file:
        # Read file
        with open(args.file, 'rb') as raw:
            raw_read = raw.read()
            raw.close()
            
        mod_iter = iter(decode_module(raw_read, decode_name_subsections=True))
        
        # Disassemble OR Generate JSON Rule
        if args.genRule or args.disassemble:
            if args.disassemble: print('[+] Disassembling {}'.format(str(args.file)))
            if args.genRule: print('[+] Generating JSON rule for {}'.format(str(args.file)))

            print('    Disassembling .wasm...')
            mod_obj.disassemble(mod_iter) # disassemble
            print('    Profiling .wasm...')
            mod_obj.profile_module()
            print('    Analysing .wasm cfg...')
            mod_obj.analyse_cfg()

            # Export disassemble results
            mod_obj.export_dis_txt(args.file) # Write out Module information
            mod_obj.export_dis_wat(args.file) # Write out Module pseudo wat
            if args.disassemble: print('- Disassembling complete, output saved in Output/ folder')

            # Save json rule
            if args.genRule:
                mod_obj.export_rule_json(args.file)
                print('- Rule generated, output saved in Output/ folder')

        # Analyse .wasm against JSON
        if args.analyse:
            print('[+] {} Analyzing {}'.format('Quick' if args.analyse == '1' else 'Deep', str(args.file)))
            analyse_level = int(args.analyse) if args.analyse == '1' or '2' else 1
            if not args.rule: # Temp check, need to fix in argparse
                print('    [!] specify json rule with -r <filename.json>')
                return

            # Load rule in Rule obj
            with open(args.rule) as rule_raw:
                rule_json = json.load(rule_raw)
                rule_obj.load_json(rule_json)

            # Disassemble wasm -> profile -> analyse CFG
            print('    Disassembling .wasm...')
            mod_obj.disassemble(mod_iter) # disassemble
            print('    Profiling .wasm...')
            mod_obj.profile_module()
            print('    Analysing .wasm cfg...')
            mod_obj.analyse_cfg()
            
            print('    Analyzing .wasm against .json...')
            an_obj.analyse(mod_obj, rule_obj, analyse_level) # Conduct analysis
            an_obj.export_results(args.file)
            print('- Anaylsis completed, output saved in Output/ folder')

        # Implementation of Call Graph Function 
        if args.gen_callgraph:
            subprocess.Popen(["./resources/executables/wasp.exe", "callgraph", args.file, "-o","output/graph.dot"],  
                                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).wait() # Run wasp.exe to generate call graph and output to a file
            render('dot', 'svg', "output/graph.dot") # Convert dot file to svg file  
            print("[+] Call graph is generated as graph.dot in the output directory\n")

        # Implementation of Control Flow Graph Function 
        if args.gen_control_flow_graph:
            if args.func: # Check if user supplied a function name 
                subprocess.Popen(["./resources/executables/wasp.exe", "cfg", "-f", args.func, args.file, "-o","output/{}_cfg.dot".format(args.func)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).wait() # Run wasp.exe to generate control flow graph and output to a file
                render('dot', 'svg', "output/{}_cfg.dot".format(args.func)) # Convert dot file to svg file  
                print("[+] Control flow graph is generated as {}_cfg.dot in the output directory\n".format(args.func))
            else: 
                logging.error('specify function name with the parameter -func <func_name>')
                sys.exit(1)
        
        # Implementation of Data Flow Graph Function 
        if args.gen_data_flow_graph:
            if args.func: # Check if user supplied a function name f 
                subprocess.Popen(["./resources/executables/wasp.exe", "dfg", "-f", args.func, args.file, "-o","output/{}_dfg.dot".format(args.func)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).wait() # Run wasp.exe to generate control flow graph and output to a file
                render('dot', 'svg', "output/{}_dfg.dot".format(args.func))  # Convert dot file to svg file 
                print("[+] Data flow graph is generated as {}_dfg.dot in the output directory\n".format(args.func))
            else: 
                logging.error('specify function name with the parameter -func <func_name>')
                sys.exit(1)
        
        # Implementation of yara malware detection
        if args.yara_rules:
            filepath_dict = {} # Dictionary to store filepaths
            i = 0
            for filename in glob.iglob(f'{"resources/yara_rules"}/*.yar'): # loop thorough resource/yara_rules directory
                filepath_dict["rule_file"+str(i)] = filename # Add filepath to dictionary
                i+=1
            matches = yara.compile(filepaths=filepath_dict).match(filepath=args.file) # Compile yara rules and match against the wasm file
            print("[+] Yara Rules Matches: ")
            for match in matches: 
                print("... [+] Rule Name: {}".format(match))
                print("..... [+] Meta - Description: {}".format(match.meta.get('description')))
                print("..... [+] Meta - Author: {}".format(match.meta.get('author')))
                print("..... [+] Meta - Date: {}".format(match.meta.get('date')))
                print("..... [+] Strings: ")
                for i in match.strings:
                    print("....... [+] {}".format(i[2].decode("utf-8")))
                print("-----------------------------------------------------")
if __name__ == '__main__':
    main()
