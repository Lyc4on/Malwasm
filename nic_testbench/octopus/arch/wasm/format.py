# MIT License

# Copyright (c) 2018 QuoScient GmbH

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from octopus.arch.wasm.constant import LANG_TYPE


def format_func_name(name, param_str, return_str):
    result = '{} '.format(return_str) if return_str else ''
    return ('{}{}({})'.format(result, name, param_str))


def format_bb_name(function_id, offset):
    return ('block_%x_%x' % (function_id, offset))


def format_kind_function(f_type):
    return f_type


def format_kind_table(element_type, flags, initial, maximum):
    return {'element_type': LANG_TYPE.get(element_type),
            'limits_flags': flags,
            'limits_initial': initial,
            'limits_maximum': maximum}


def format_kind_memory(flags, initial, maximum):
    return {'limits_flags': flags,
            'limits_initial': initial,
            'limits_maximum': maximum}


def format_kind_global(content_type, mutability):
    return (content_type, mutability)
