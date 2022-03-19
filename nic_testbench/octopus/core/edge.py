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

EDGE_UNCONDITIONAL = 'unconditional'
EDGE_CONDITIONAL_TRUE = 'conditional_true'
EDGE_CONDITIONAL_FALSE = 'conditional_false'
EDGE_FALLTHROUGH = 'fallthrough'
EDGE_CALL = 'call'


class Edge:

    def __init__(self, node_from, node_to, edge_type=EDGE_UNCONDITIONAL,
                 condition=None):

        self.node_from = node_from
        self.node_to = node_to
        self.type = edge_type
        self.condition = condition

    def __str__(self):
        return str(self.as_dict())

    def __eq__(self, other):
        return self.node_from == other.node_from and\
            self.node_to == other.node_to and\
            self.type == other.type and\
            self.condition == other.condition

    def __hash__(self):
        return hash(('from', self.node_from,
                     'to', self.node_to,
                     'type', self.type,
                     'condition', self.condition))

    def as_dict(self):
        return {'from': str(self.node_from), 'to': str(self.node_to),
                'type': self.type, 'condition': self.condition}
