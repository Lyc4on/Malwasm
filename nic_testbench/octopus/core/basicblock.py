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

class BasicBlock(object):
    """
    """
    def __init__(self, start_offset=0x00, start_instr=None,
                 name='block_default_name'):
        self.start_offset = start_offset
        self.start_instr = start_instr
        self.name = name
        self.end_offset = start_offset
        self.end_instr = start_instr
        self.instructions = list()

        self.states = []
        self.function_name = "unknown"

    @property
    def size(self):
        return self.end_offset - self.start_offset

    def __str__(self):
        out = ''
        line = ''
        line = str(self.start_offset) + ': ' + str(self.name) + '\n'
        line += 'start_instr = ' + str(self.start_instr.name) + '\n'
        line += 'size = ' + str(self.size) + '\n'
        line += 'end_offset = ' + str(self.end_offset) + '\n'
        line += 'end_instr = ' + str(self.end_instr.name) + '\n'
        line += 'function_name = ' + str(self.function_name) + '\n'
        out += line + '\n\n'
        return out

    def instructions_details(self, format='hex'):
        out = ''
        line = ''
        for i in self.instructions:
            line = '%x: ' % i.offset
            if i.operand is not None and not i.xref:
                line += '%s' % str(i)
            elif isinstance(i.xref, list) and i.xref:
                line += '%s %s' % (i.name, i.xref)
            elif isinstance(i.xref, int) and i.xref:
                line += '%s %x' % (i.name, i.xref)
            elif i.operand_interpretation:
                line += i.operand_interpretation
            else:
                line += i.name + ' '

            out += line + '\n'
        return out

    def instructions_ssa(self, format='hex'):
        out = ''
        line = ''
        for i in self.instructions:
            line = '%x: ' % i.offset
            if i.ssa:
                line += '' + i.ssa.format()
            else:
                line += '[NO_SSA] ' + i.name
            out += line + '\n'
        return out
