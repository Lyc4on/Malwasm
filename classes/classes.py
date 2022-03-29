from pyclbr import Function
import re
import itertools

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
            returnStr += str(func.profile) + '\n'
        return returnStr

class Function():
    # Local variables
    param_section = ''
    result_section = ''
    local_section = ''
    insn_arr = []
    insn_count = 0
    profile = {}
    id = 0

    def __init__(self, id, func_body, func_type=None):
        self.id = id
        self.param_section = utils.get_param_sect(func_type)
        self.local_section = utils.get_local_sect(func_body)
        self.insn_arr = utils.get_insn_arr(func_body)
        self.insn_count = len(self.insn_arr)
        self.profile = utils.get_profile(self.insn_arr)
    
    def __str__(self):
        returnStr = 'func_id: ' + str(self.id) + '\n' + 'param_sect: ' + self.param_section + '\n'
        returnStr += 'result_sect: ' + self.result_section + '\n'
        returnStr += 'local_sect: ' + self.local_section + '\n'
        returnStr += 'insn_count: ' + str(self.insn_count) + '\n'
        returnStr += 'profile: ' + str(self.profile) + '\n\n'
        return returnStr