import struct
from .AllocatedArea import AllocatedArea, AllocatedAreaMagic


class X86Context:
    def __init__(self, infile):
        self.register_values = list()
        for i in range(0, 7):
            reg_val = struct.unpack_from('Q', infile.read(struct.calcsize("Q")))[0]
            self.register_values.append(reg_val)
        self.return_value = struct.unpack_from('c', infile.read(struct.calcsize('c')))[0]
        self.allocated_areas = list()
        for idx in range(0, len(self.register_values)):
            reg = self.register_values[idx]
            if reg == AllocatedAreaMagic and idx < len(self.register_values) - 1:
                self.allocated_areas.append(AllocatedArea(infile))

    def __hash__(self):
        hash_sum = 0

        for reg in self.register_values:
            hash_sum = hash((hash_sum, reg))

        for area in self.allocated_areas:
            hash_sum = hash((hash_sum, area))

        return hash_sum

    def __eq__(self, other):
        return hash(self) == hash(other)

    def write_bin(self, infile):
        for reg in self.register_values:
            infile.write(struct.pack('Q', reg))
        infile.write(struct.pack('c', self.return_value))

        for subarea in self.allocated_areas:
            subarea.write_bin(infile)
