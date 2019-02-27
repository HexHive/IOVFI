import struct
from .AllocatedArea import AllocatedArea, AllocatedAreaMagic


class X86Context:
    def __init__(self, file):
        self.register_values = list()
        for i in range(0, 7):
            reg_val = struct.unpack_from('Q', file.read(struct.calcsize("Q")))[0]
            self.register_values.append(reg_val)
        self.allocated_areas = list()
        for idx in range(0, len(self.register_values)):
            reg = self.register_values[idx]
            if reg == AllocatedAreaMagic and idx < len(self.register_values) - 1:
                self.allocated_areas.append(AllocatedArea(file))

    def __hash__(self):
        hash_sum = 0

        for reg in self.register_values:
            hash_sum = hash((hash_sum, reg))

        for area in self.allocated_areas:
            hash_sum = hash((hash_sum, area))

        return hash_sum

    def __eq__(self, other):
        return hash(self) == hash(other)

    def write_bin(self, file):
        for reg in self.register_values:
            file.write(struct.pack('Q', reg))

        for subarea in self.allocated_areas:
            subarea.write_bin(file)
