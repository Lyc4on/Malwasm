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


def search_in_list_of_dict(string_to_search, target_list, key_dict):
    return list(filter(lambda elem: str(string_to_search) in str(elem[key_dict]), target_list))
