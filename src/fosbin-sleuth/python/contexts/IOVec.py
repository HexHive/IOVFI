import hashlib
import sys

from .X86Context import X86Context


class IOVec:
    def __init__(self, in_file):
        self.input = X86Context(in_file)
        self.output = X86Context(in_file)

    def __hash__(self):
        return hash((self.input, self.output))

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def _get_hash_obj(self):
        hash_sum = hashlib.md5()
        hash_sum.update(hash(self).to_bytes(8, sys.byteorder, signed=True))
        return hash_sum

    def write_bin(self, out_file):
        self.input.write_bin(out_file)
        self.output.write_bin(out_file)

    def hexdigest(self):
        hash_sum = self._get_hash_obj()
        return hash_sum.hexdigest()

    def size_in_bytes(self):
        return self.input.size_in_bytes() + self.output.size_in_bytes()
