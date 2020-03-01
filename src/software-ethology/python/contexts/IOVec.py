import hashlib
import struct

from .X86Context import X86Context


class IOVec:
    def __init__(self, in_file):
        self.input = X86Context(in_file)
        self.output = X86Context(in_file)

        syscall_count = struct.unpack_from('N', in_file.read(struct.calcsize('N')))[0]
        self.syscalls = list()
        for idx in range(0, syscall_count):
            self.syscalls.append(struct.unpack_from('Q', in_file.read(struct.calcsize('Q')))[0])
        self.syscalls.sort()

    def __hash__(self):
        return int(self._get_hash_obj().hexdigest(), 16)

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def _get_hash_obj(self):
        hash_sum = hashlib.sha256()
        in_hash = hash(self.input)
        out_hash = hash(self.input)
        hash_sum.update(struct.pack('N', in_hash))
        hash_sum.update(struct.pack('N', out_hash))

        for syscall in self.syscalls:
            hash_sum.update(struct.pack('Q', syscall))
        return hash_sum

    def write_bin(self, out_file):
        self.input.write_bin(out_file)
        self.output.write_bin(out_file)

    def hexdigest(self):
        hash_sum = self._get_hash_obj()
        return hash_sum.hexdigest()

    # def size_in_bytes(self):
    #     return self.input.size_in_bytes() + self.output.size_in_bytes()
