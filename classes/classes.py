import enum
import profile
from pyclbr import Function
import re
import itertools
import json
import os

from collections import OrderedDict
from utils import utils

from wasm import (
    decode_module, decode_bytecode,
    format_instruction, format_lang_type, 
    format_mutability, format_function,
    SEC_DATA, SEC_ELEMENT, SEC_GLOBAL,
    SEC_CODE, SEC_TYPE, SEC_FUNCTION, 
    SEC_IMPORT, SEC_EXPORT, Section,
    INSN_ENTER_BLOCK,
    INSN_LEAVE_BLOCK,)

class Analysis():
    buffer_ratio = 0 # Our buffer ratio offset
    filtered_funcs = [] # Array to store filtered mod_obj functions to analyze

    def __init__(self):
        pass

    def analyse(self, mod_obj, rule_obj):
        """
        1. Find smallest ratio in rule_obj
        2. Find all func in mod_obj where ratio >= smallest ratio
        3. Check filtered_funcs distribution for deep analysis
        """
        min_rule_dist = min(rf['func_dist'] for rf in rule_obj.profile.values()) # 1.
        for func in mod_obj.func_objs:
            if func.ratio >= (min_rule_dist - self.buffer_ratio):
                self.filtered_funcs.append(func)
                print(func)       

class Rule():
    name = ''
    profile = {}
    cfg = {}

    def __init__(self):
        # Read/Parse rules into local variables
        pass

    def load_json(self, in_json):
        if in_json:
            self.name = in_json.get('name', '')
            self.profile = in_json.get('profile', {})
            self.cfg = in_json.get('cfg', {})
        pass

    def __str__(self):
        returnStr = '{b} {name} Rule {b}\n\n'.format(b="="*20, name=self.name)
        returnStr += '{b} Rule Profile {b}\n\n'.format(b="="*26)
        returnStr += 'profile: {j}\n\n'.format(j=json.dumps(self.profile, sort_keys=True, indent=4))
        returnStr += '{b} CFG Information {b}\n\n'.format(b="="*26)
        called_by = json.dumps(self.cfg, sort_keys=True, indent=2)
        returnStr += 'CFG - {{ called: caller_A : count, ... }}:\n{j}\n\n'.format(j=called_by)
        return returnStr
        # returnStr += '{b} Functions Profile {b}\n\n'.format(b="="*25)

class Module():
    func_objs = []
    profile = {} # 
    called_by = {} # { called_id: {caller_id: count,...}, ...}

    def __init__(self):
        pass
    
    def disassemble(self, mod_iter):
        code_sec = type_sec =  func_sec = None
        import_sec = export_sec = None
        func_id = 0

        for cur_sec, cur_sec_data in mod_iter:
            if type(cur_sec) == Section:
                if cur_sec_data.id == SEC_CODE:
                    code_sec = cur_sec_data.payload
                    
                elif cur_sec_data.id == SEC_TYPE:
                    type_sec = cur_sec_data.payload

                elif cur_sec_data.id == SEC_FUNCTION:
                    func_sec = cur_sec_data.payload

                elif cur_sec_data.id == SEC_IMPORT:
                    import_sec = cur_sec_data.payload

                elif cur_sec_data.id == SEC_EXPORT:
                    export_sec = cur_sec_data.payload

        # TMP GET export - get function name export
        if export_sec is not None:
            # print('Export Section:')
            for idx, entry in enumerate(export_sec.entries):
                # entry.index = func id || entry.field_str = func export name eg. cryptonight...
                # print('{a} {b}'.format(a=entry.index, b=entry.field_str.tobytes()))
                pass

        # GET starting id for func
        if import_sec is not None:
            func_count = 0
            for idx, entry in enumerate(import_sec.entries):
                func_count += 1 if entry.kind != 0 else 0
            func_count = import_sec.count - func_count
        
        # Disassemble
        if code_sec is not None:
            for i, func_body in enumerate(code_sec.bodies):
                # If we have type info, use it.
                func_type = type_sec.entries[func_sec.types[i]] if (
                    None not in (type_sec, func_sec)
                ) else None
                
                func_obj = Function(func_count, func_body, func_type) # Create Function object
                self.add_func(func_obj) # Add Function obj to module object
                func_count += 1


    def profile_module(self):
        if self.func_objs: # if arr is not empty
            self.func_objs.sort(key=lambda x: x.func_dist['func_dist'], reverse=True)
            # Debug
            # print(''.join(['id: {id}\nprofile: {p}\n'.format(id=str(i.id), p=i.func_dist) for i in self.func_objs[:5]]))
            length = 5 if len(self.func_objs) >= 5 else len(self.func_objs)            
            for func in self.func_objs[:length]:
                self.profile[func.id] = func.func_dist

    def analyse_cfg(self):
        if self.func_objs:
            for func in self.func_objs:
                # Set counter default 0 if key don't exist
                self.called_by[str(func.id)] = self.called_by.get(str(func.id), {})
                
                # print(self.called_by[str(func.id)])
                caller_id = str(func.id)
                if func.calls_arr: # if not empty
                    for called in func.calls_arr:
                        called_id = str(called)
                        self.called_by[called_id] = self.called_by.get(called_id, {}) # set if key not exist yet
                        current_count = self.called_by[called_id].get(caller_id, 0) # set 0 if not exist
                        self.called_by[called_id][caller_id] = current_count+1 if current_count > 0 else 1

    def export_dis_txt(self, abs_path):
        of_str_t = abs_path.split(os.sep)[-1] # Get the ../../<of_str.wasm>
        of_str_t = of_str_t.split('.')[0] + '_dis.txt'
        of_path_t = os.getcwd() + os.sep + of_str_t
        mod_of_t = open(of_path_t, 'w')
        mod_of_t.write(str(self))
        mod_of_t.close()

    def export_dis_wat(self, abs_path):
        of_str_w = abs_path.split(os.sep)[-1] # Get the ../../<of_str.wasm>
        of_str_w = of_str_w.split('.')[0] + '_dis.wat'
        of_path_w = os.getcwd() + os.sep + of_str_w
        mod_of_w = open(of_path_w, 'w')
        mod_of_w.write(self.get_wat())
        mod_of_w.close()

    def export_rule_json(self, abs_path):
        tmp_name = of_str = abs_path.split(os.sep)[-1] # Get the ../../<of_str.wasm>
        of_str = of_str.split('.')[0] + '_rule.json'
        of_path = os.getcwd() + os.sep + of_str
        with open(of_path, "w") as write_file:
            json_to_write = self.generate_rule(tmp_name)
            json.dump(json_to_write, write_file, indent=2)
            write_file.close()

    def generate_rule(self, input_file_name): # Returns json string
        call_signature = {}
        # print(''.join(['id: {id}\nprofile: {p}\n'.format(id=str(i.id), p=i.func_dist) for i in self.func_objs[:5]]))
        for key in self.profile.keys():
            call_signature[key] = self.called_by.get(str(key), {})

        call_signature = OrderedDict(sorted(call_signature.items()))
        # print(self.profile)
        rule_json = { 
            'name' : input_file_name, 
            'profile' : self.profile,
            'cfg' : call_signature
            }
        return rule_json

    def add_func(self, func):
        if not isinstance(func, Function):
            raise ValueError("Can't add non-Function objects to func_objs array")
        else:
            self.func_objs.append(func)
    
    def get_wat(self):
        returnStr = ''
        if self.func_objs:
            returnStr = ''.join(func.get_wat() for func in self.func_objs)
        return returnStr

    def __str__(self):
        returnStr = '{b} CFG Information {b}\n\n'.format(b="="*26)
        called_by = json.dumps(self.called_by, sort_keys=True, indent=2)
        returnStr += 'CFG - {{ called: caller_A : count, ... }}:\n{j}\n\n'.format(j=called_by)
        returnStr += '{b} Module Profile {b}\n\n'.format(b="="*26)
        returnStr += 'profile: {j}\n\n'.format(j=json.dumps(self.profile, sort_keys=True, indent=4))
        returnStr += '{b} Functions Profile {b}\n\n'.format(b="="*25)
        for func in self.func_objs:
            returnStr += '{}\n'.format(func)
        return returnStr

class Function():
    # Local variables
    param_section = insn_arr = calls_arr = []
    result_section = local_section = '' # always a single return type
    insn_count = id = blocks_count = 0
    profile = {}
    ratio = 0.0
    func_dist = {}
    
    def __init__(self, id, func_body, func_type=None):
        self.id = id
        self.param_section = utils.get_param_sect(func_type)
        self.result_section = utils.get_result_sect(func_type)
        self.local_section = utils.get_local_sect(func_body)
        self.insn_arr = utils.get_insn_arr(func_body)
        self.insn_count = len(self.insn_arr)
        self.profile = utils.get_profile(self.insn_arr)

        self.blocks_count = utils.get_blocks_count(self.profile)
        self.ratio = self.insn_count/self.blocks_count
        
        # Add to call <func ID> if exist, else remain as None
        self.calls_arr = utils.get_calls_arr(self.insn_arr)
        self.func_dist = utils.get_func_dist(self.profile, self.insn_count, self.ratio)
    
    def get_wat(self):
        returnStr = '(func (;{id};) '.format(id=self.id)
        if self.param_section:
            returnStr += '(param {p}) '.format(p=''.join(pa+' ' for pa in self.param_section))
        if self.result_section:
            returnStr += '(result {r})\n'.format(r=self.result_section)
        if self.local_section:
            returnStr += '(local {l})\n'.format(l=self.local_section)
        returnStr += 'instructions: \n{i}\n'.format(i=''.join(o+'\n' for o in self.insn_arr))
        return returnStr

    def __str__(self):
        returnStr = 'func_name: func_{id}\n'.format(id=self.id)
        returnStr += 'insn_count: {c}\n'.format(c=str(self.insn_count))
        returnStr += 'blocks: {b}\n'.format(b=str(self.blocks_count))
        returnStr += 'ratio: {:.2f}\n'.format(self.ratio)
        returnStr += 'func_dist: {:.2f}\n'.format(self.func_dist['func_dist'])
        returnStr += 'calls: {c}\n'.format(c=''.join(str(ca)+' ' for ca in self.calls_arr))
        returnStr += 'param: {p}\n'.format(p=''.join(pa+' ' for pa in self.param_section))
        returnStr += 'result: {r}\n'.format(r=self.result_section)
        returnStr += 'profile: {j}\n\n'.format(j=json.dumps(self.profile, sort_keys=True, indent=4))
        # returnStr += 'instructions: \n{i}\n'.format(i=''.join(o+'\n' for o in self.insn_arr))
        return returnStr
    

