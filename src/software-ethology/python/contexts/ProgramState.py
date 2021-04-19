import hashlib
import struct

import sys


class RangeMapValue:
    def __init__(self, infile):
        self.addr_min = \
        struct.unpack_from("Q", infile.read(struct.calcsize('Q')))[0]
        self.addr_max = \
        struct.unpack_from("Q", infile.read(struct.calcsize('Q')))[0]
        self.val = struct.unpack_from("Q", infile.read(struct.calcsize('Q')))[0]

    def pretty_print(self, out=sys.stdout):
        print("[ {0:#0{1}x} -- {2:#0{1}x} ] = {3}".format(self.addr_min, 18,
                                                          self.addr_max,
                                                          self.val), file=out)

    def to_bytes(self):
        result = bytearray()
        result.extend(
            struct.pack("=QQQ", self.addr_min, self.addr_max, self.val))
        return result


class RangeMap:
    def __init__(self, infile):
        range_map_size = \
        struct.unpack_from('I', infile.read(struct.calcsize('I')))[0]
        self.entries = list()
        for i in range(range_map_size):
            self.entries.append(RangeMapValue(infile))

    def pretty_print(self, out=sys.stdout):
        for e in self.entries:
            e.pretty_print(out)

    def to_bytes(self):
        result = bytearray()
        result.extend(struct.pack('I', len(self.entries)))
        for entry in self.entries:
            result.extend(entry.to_bytes())
        return result


class RegisterValue:
    def __init__(self, infile):
        self.guest_state_offset = \
        struct.unpack_from("i", infile.read(struct.calcsize("i")))[0]
        self.value = struct.unpack_from("Q", infile.read(struct.calcsize("Q")))[
            0]
        self.is_ptr = \
        struct.unpack_from("?", infile.read(struct.calcsize("?")))[0]

    def pretty_print(self, out=sys.stdout):
        if self.is_ptr:
            indicator = "O"
        else:
            indicator = "X"
        print("{0}:\t{1:#0{2}x} {3}".format(self.guest_state_offset, self.value,
                                            18, indicator), file=out)

    def to_bytes(self):
        result = bytearray()
        result.extend(struct.pack("=iQ?", self.guest_state_offset, self.value,
                                  self.is_ptr))
        return result


class ProgramState:
    def __init__(self, infile):
        register_state_count = \
        struct.unpack_from("N", infile.read(struct.calcsize("N")))[0]
        self.register_values = list()
        for i in range(register_state_count):
            self.register_values.append(RegisterValue(infile))
        self.address_space = RangeMap(infile)
        self.pointer_locations = RangeMap(infile)

    def pretty_print(self, out=sys.stdout):
        print('Register Values:', file=out)
        for rv in self.register_values:
            print("\t", end='', file=out)
            rv.pretty_print(out)
        print('Address Space:', file=out)
        self.address_space.pretty_print(out)
        print('Pointer Locations:', file=out)
        self.pointer_locations.pretty_print(out)

    def __hash__(self):
        hash_sum = hashlib.sha256()
        hash_sum.update(self.to_bytes())

        return int(hash_sum.hexdigest(), 16)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def to_bytes(self):
        result = bytearray()

        result.extend(struct.pack('N', len(self.register_values)))
        for val in self.register_values:
            result.extend(val.to_bytes())
        result.extend(self.address_space.to_bytes())
        result.extend(self.pointer_locations.to_bytes())

        return result
