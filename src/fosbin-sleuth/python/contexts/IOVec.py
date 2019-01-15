from .X86Context import *


class IOVec:
    def __init__(self, file):
        self.input = X86Context(file)
        self.output = X86Context(file)

    def __hash__(self):
        return hash()

    def hash(self):
        hash = hashlib.md5()
        hash.update(self.input.hash().encode('utf-8'))
        hash.update(self.output.hash().encode('utf-8'))

        return hash.hexdigest()

    def write_bin(self, file):
        self.input.write_bin(file)
        self.output.write_bin(file)
