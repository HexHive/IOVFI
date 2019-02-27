import hashlib
from .X86Context import X86Context


class IOVec:
    def __init__(self, file):
        self.input = X86Context(file)
        self.output = X86Context(file)

    def __hash__(self):
        return hash((self.input, self.output))

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def _get_hash_obj(self):
        hash_sum = hashlib.md5()
        hash_sum.update(hash(self))
        return hash_sum

    def write_bin(self, file):
        self.input.write_bin(file)
        self.output.write_bin(file)

    def hexdigest(self):
        hash_sum = self._get_hash_obj()
        return hash_sum.hexdigest()
