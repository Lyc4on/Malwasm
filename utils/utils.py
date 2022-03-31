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
        local_section = '{}'.format(' '.join(itertools.chain.from_iterable(
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

def get_calls_arr(insn_arr):
    returnArr = [x.strip().split(' ',1) for x in insn_arr] # Strip whitespace
    returnArr = [x[-1] for x in returnArr if 'call' in x] # Filter to only keep call <funcID>
    return returnArr

def get_blocks_count(profile):
    count = 0
    block_insn = ['block', 'loop', 'if', 'else', 'br', 'br_if', 
                    'br_table', 'return', 'call_indirect']
    
    for ins in block_insn:
        if ins == 'call' or ins == 'call_indirect':
            count += 1
        else:
            count += profile.get(ins, 0) # Get count, 0 if not exist
    if count == 0:
        count += 1
    return count

def get_func_dist(profile, insn_count, func_ratio):
    returnProfile = {}
    insn = ['i32.add', 'i32.and', 'i32.shl', 'i32.shr_u', 'i32.xor']
    total_insn_count = 0
    
    for ins in insn:
        value = profile.get(ins, 0) # get value, if None then set 0
        returnProfile[ins] = value
        total_insn_count += value
    
    # Get local_dist of each ins in returnProfile
    returnProfile = {k:round(v/total_insn_count, 2) if v > 0 else 0 
                    for (k,v) in returnProfile.items()}

    # Overall 'dist' = total_insn_count of i32.../insn_count of function
    returnProfile['func_dist'] = round(total_insn_count/insn_count, 2)
    returnProfile['ratio'] = round(func_ratio, 2)
    
    return returnProfile

def get_profile(insn_arr):
    profile = {}
    # Strip whitespace and then split to keep only first string of each element in insn_arr
    insn_arr_strip = [x.strip().split(' ',1)[0] for x in insn_arr]
    
    # Count each opcode in array
    for op in insn_arr_strip:
        profile[op] = profile.get(op, 0) + 1 # get op and add 1 to count; assign 0 if op(key) not found

    return profile
