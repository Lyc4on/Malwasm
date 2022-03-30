import re
import itertools

from wasm import (
    decode_module, decode_bytecode,
    format_instruction, format_lang_type, 
    format_mutability, format_function,
    SEC_DATA, SEC_ELEMENT, SEC_GLOBAL,
    SEC_CODE, SEC_TYPE, SEC_FUNCTION, Section,
    INSN_ENTER_BLOCK,
    INSN_LEAVE_BLOCK,)

from binascii import unhexlify

def bytecode_to_bytes(bytecode):
    if str(bytecode).startswith("0x"):
        bytecode = bytecode[2:]

    try:
        # python > 2.7
        bytecode = bytes.fromhex(bytecode)
    except AttributeError:
        # python <= 2.7
        try:
            bytecode = bytecode.decode("hex")
        except TypeError:
            # last chance
            try:
                bytecode = unhexlify(bytecode)
            except:
                pass
    # already bytes or bytearray
    except TypeError:
        pass
    return bytecode

def get_param_sect(func_type):
    param_section = []
    # Extract func signature        
    if func_type is None:
        pass
    else:
        p = '{}'.format(' '.join(
            map(format_lang_type, func_type.param_types)
            )) if func_type.param_types else ''
    param_section = p.split(' ')

    return param_section

def get_result_sect(func_type):
    result_section = ''
    if func_type is None:
        pass
    else:
        result_section = '{}'.format(
            format_lang_type(func_type.return_type)
            ) if func_type.return_type else ''
    return result_section

def get_local_sect(func_body):
    local_section = ''
    # Extract local variable declaration        
    if func_body.locals:
        local_section = 'locals {}'.format(' '.join(itertools.chain.from_iterable(
            itertools.repeat(format_lang_type(x.type), x.count) 
            for x in func_body.locals
        )))
    return local_section

def get_insn_arr(func_body):
    # Extract func body
    insn_arr = []
    level = 1
    indent = 2
            
    for cur_insn in decode_bytecode(func_body.code):
        if cur_insn.op.flags & INSN_LEAVE_BLOCK:
            level -= 1
        insn_arr.append(' ' * (level * indent) + format_instruction(cur_insn))
        if cur_insn.op.flags & INSN_ENTER_BLOCK:
            level += 1
    return insn_arr

def get_profile(insn_arr):
    profile = {}
    # Strip whitespace and then split to keep only first string of each element in insn_arr
    insn_arr_strip = [x.strip().split(' ',1)[0] for x in insn_arr]
    
    # Add block key into profile - every func has 1 block by default
    profile['block'] = profile.get('block', 1)

    # Count each opcode in array
    for op in insn_arr_strip:
        profile[op] = profile.get(op, 0) + 1 # get op and add 1 to count; assign 0 if op(key) not found

    return profile