import hashlib
import os
from .X86Context import X86Context


class IOVec:
    def __init__(self, file):
        self.input = X86Context(file)
        self.output = X86Context(file)

    def __hash__(self):
        return self.hash()

    def hash(self):
        hash_sum = hashlib.md5()
        hash_sum.update(str(self.input.hash()).encode('utf-8'))
        hash_sum.update(str(self.output.hash()).encode('utf-8'))

        return hash(hash_sum)

    def write_bin(self, file):
        self.input.write_bin(file)
        self.output.write_bin(file)
