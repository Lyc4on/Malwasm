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

# Creates WModule object
# class WModule:
#     def __init__(self, func_body, func_type=None):

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
    ratio = 0.0

    def __init__(self, id, func_body, func_type=None):
        self.id = id
        self.param_section = utils.get_param_sect(func_type)
        self.result_section = utils.get_result_sect(func_type)
        self.local_section = utils.get_local_sect(func_body)
        self.insn_arr = utils.get_insn_arr(func_body)
        self.insn_count = len(self.insn_arr)
        self.profile = utils.get_profile(self.insn_arr)
        self.ratio = self.insn_count/self.profile['block']
    
    def __str__(self):
        # returnStr = 'func_id: ' + str(self.id) + '\n' + 'param_sect: ' + self.param_section + '\n'
        # returnStr += 'result_sect: ' + self.result_section + '\n'
        # returnStr += 'local_sect: ' + self.local_section + '\n'
        # returnStr += 'insn_count: ' + str(self.insn_count) + '\n'
        # returnStr += 'profile: ' + str(self.profile) + '\n\n'
        returnStr = 'func_name: func_{id}\n'.format(id=self.id)
        returnStr += 'param: {p}\n'.format(p=''.join(pa+' ' for pa in self.param_section))
        returnStr += 'result: {r}\n'.format(r=self.result_section)
        returnStr += 'insn_count: {c}\n'.format(c=str(self.insn_count))
        returnStr += 'blocks: {b}\n'.format(b=str(self.profile['block']))
        returnStr += 'ratio: {r}\n'.format(r=str(self.ratio))
        returnStr += 'instructions: \n{i}\n'.format(i=''.join(o+'\n' for o in self.insn_arr))
        returnStr += 'profile: {j}\n\n'.format(j=json.dumps(self.profile, sort_keys=True, indent=4))
        return returnStr