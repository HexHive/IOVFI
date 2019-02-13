import struct
import sys
import hashlib
from .FBLogging import logger

AllocatedAreaMagic = 0xA110CA3D


class AllocatedArea:

    def __init__(self, file):
        self.size = struct.unpack_from("Q", file.read(8))[0]
        if self.size > 1024:
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

    def __hash__(self):
        return self.hash()

    def hash(self):
        i = 0
        curr_subarea = 0
        hash_sum = hashlib.md5()
        while i < self.size:
            if self.mem_map[i]:
                sub_hash = hash(self.subareas[curr_subarea])
                hash_sum.update(str(sub_hash).encode("utf-8"))
                curr_subarea += 1
                i += 8
            else:
                hash_sum.update(struct.pack("B", self.data[i]))
                i += 1

        return hash(hash_sum)

    def write_bin(self, file):
        file.write(struct.pack("Q", self.size))
        for i in range(0, self.size):
            file.write(struct.pack("?", self.mem_map[i]))

        for i in range(0, self.size):
            file.write(struct.pack("B", self.data[i]))

        for subarea in self.subareas:
            subarea.write_bin(file)
