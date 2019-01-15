import hashlib
from .AllocatedArea import *


class X86Context:
    def __init__(self, file):
        self.register_values = list()
        for i in range(0, 7):
            reg_val = struct.unpack_from('Q', file.read(8))[0]
            self.register_values.append(reg_val)
        self.allocated_areas = list()
        for idx in range(0, len(self.register_values)):
            reg = self.register_values[idx]
            if reg == AllocatedAreaMagic and idx < len(self.register_values) - 1:
                self.allocated_areas.append(AllocatedArea(file))

    def hash(self):
        md5sum = hashlib.md5()
        for reg in self.register_values:
            md5sum.update(reg.to_bytes(8, sys.byteorder))
        for subarea in self.allocated_areas:
            subarea.hash(md5sum)

        return md5sum.hexdigest()

    def __hash__(self):
        return hash()

    def write_bin(self, file):
        for reg in self.register_values:
            file.write(struct.pack('Q', reg))

        for subarea in self.allocated_areas:
            subarea.write_bin(file)
