from pyclbr import Function
import re
import itertools
import json

from utils import utils

from wasm import (
    decode_module, decode_bytecode,
    format_instruction, format_lang_type, 
    format_mutability, format_function,
    SEC_DATA, SEC_ELEMENT, SEC_GLOBAL,
    SEC_CODE, SEC_TYPE, SEC_FUNCTION, Section,
    INSN_ENTER_BLOCK,
    INSN_LEAVE_BLOCK,)

class Module():
    func_objs = []

    def __init__(self):
        pass
    
    def add_func(self, func):
        if not isinstance(func, Function):
            raise ValueError("Can't add non-Function objects to func_objs array")
        else:
            self.func_objs.append(func)

    def __str__(self):
        returnStr = ''
        for func in self.func_objs:
            returnStr += '{}\n'.format(func)
        return returnStr

class Function():
    # Local variables
    param_section = []
    result_section = '' # always a single return type
    local_section = ''
    insn_arr = []
    insn_count = 0
    profile = {}
    id = 0
    blocks_count = 0
    ratio = 0.0
    calls_arr = []
    

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
    
    def __str__(self):
        returnStr = 'func_name: func_{id}\n'.format(id=self.id)
        returnStr += 'param: {p}\n'.format(p=''.join(pa+' ' for pa in self.param_section))
        returnStr += 'result: {r}\n'.format(r=self.result_section)
        returnStr += 'insn_count: {c}\n'.format(c=str(self.insn_count))
        returnStr += 'blocks: {b}\n'.format(b=str(self.blocks_count))
        returnStr += 'ratio: {:.2f}\n'.format(self.ratio)
        returnStr += 'instructions: \n{i}\n'.format(i=''.join(o+'\n' for o in self.insn_arr))
        returnStr += 'calls: {c}\n'.format(c=''.join(str(ca)+' ' for ca in self.calls_arr))
        returnStr += 'profile: {j}\n\n'.format(j=json.dumps(self.profile, sort_keys=True, indent=4))
        return returnStr