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

# modified code from https://github.com/pventuzelo/octopus/blob/master/octopus/nic_testbench/octopus/core/function.py

from octopus.arch.wasm.wasm import _groups
from collections import Counter

class Function(object):

    def __init__(self, start_offset, start_instr=None,
                 name='func_default_name', prefered_name=None):
        # parameters
        self.start_offset = start_offset
        self.start_instr = start_instr
        self.name = name
        self.prefered_name = prefered_name if prefered_name else name
        self.size = 0
        self.end_offset = None
        self.end_instr = None
        self.basicblocks = list()
        self.instructions = list()
        self.profile_instrs = dict()

    def __str__(self):
        line = ('%x' % self.start_offset) + ': ' + str(self.name) + '\n'
        line += 'prefered_name: %s\n' % self.prefered_name
        line += 'start_offset = %x\n' % self.start_offset
        line += 'start_instr = ' + str(self.start_instr.name) + '\n'
        if self.size:
            line += 'size = ' + str(self.size) + '\n'
        if self.end_offset:
            line += 'end_offset = ' + str(self.end_offset) + '\n'
        if self.end_instr:
            line += 'end_instr = ' + str(self.end_instr.name) + '\n'
        line += 'length basicblocks: %s\n' % len(self.basicblocks)
        line += 'length instructions: %s\n' % len(self.instructions)
        line += 'ratio: %s instrs/block\n' % round(len(self.instructions)/len(self.basicblocks), 2)
        
        line += 'instructions: \n'
        self.profile_instrs_per_func()

        for instr in self.instructions:
            line += '\t%s\n' % str(instr.name)

        line += 'profile: %s\n' % str(self.profile_instrs)
        line += '\n\n'
        return line

    # Custom method to profile instrs per function
    def profile_instrs_per_func(self):
        # instrs_arr = list()
        for instr in self.instructions:
            # instrs_arr.append(instr)
            self.profile_instrs[instr.name] = self.profile_instrs.get(instr.name, 0) + 1
        
        
        