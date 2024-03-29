import hashlib
import struct

AllocatedAreaMagic = 0xA110CA3D
AllocatedAreaSize = 4096


class AllocatedArea:
    def __init__(self, file):
        self.size = struct.unpack_from("Q", file.read(8))[0]
        if self.size > AllocatedAreaSize:
            raise ValueError("{} ({})".format(self.size, hex(self.size)))
        self.mem_map = [None] * self.size
        for i in range(0, self.size):
            self.mem_map[i] = struct.unpack_from("?", file.read(1))[0]

        self.subareas = list()
        self.data = [None] * self.size
        i = 0
        subareasToRead = 0
        while i < self.size:
            if self.mem_map[i]:
                subareasToRead += 1
                for j in range(0, 8):
                    self.data[i] = struct.unpack_from("B", file.read(1))[0]
                    i += 1
            else:
                self.data[i] = struct.unpack_from("B", file.read(1))[0]
                i += 1

        if subareasToRead > 0:
            for x in range(0, subareasToRead):
                self.subareas.append(AllocatedArea(file))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        hash_sum = hashlib.sha256()

        for i in range(0, self.size):
            hash_sum.update(struct.pack('B', self.data[i]))

        for area in self.subareas:
            hash_sum.update(hash(area))

        return int(hash_sum.hexdigest(), 16)

    def write_bin(self, file):
        file.write(struct.pack("Q", self.size))
        for i in range(0, self.size):
            file.write(struct.pack("?", self.mem_map[i]))

        for i in range(0, self.size):
            file.write(struct.pack("B", self.data[i]))

        for subarea in self.subareas:
            subarea.write_bin(file)

    def size_in_bytes(self):
        total_size = struct.calcsize('Q')
        for i in range(0, self.size):
            total_size += struct.calcsize('?')
            total_size += struct.calcsize('B')

        for subarea in self.subareas:
            total_size += subarea.size_in_bytes()

        return total_size
