import hashlib
import struct


class ProgramState:
    def __init__(self, infile):
        register_state_size = struct.unpack_from("N", infile.read(struct.calcsize("N")))[0]
        fmt = 'B' * register_state_size
        self.register_state = struct.unpack_from(fmt, infile.read(struct.calcsize(fmt)))

        address_space_size = struct.unpack_from('I', infile.read(struct.calcsize('I')))[0]
        self.address_state = list()
        for i in range(address_space_size):
            (addr_min, addr_max, val) = struct.unpack_from('=QQQ', infile.read(struct.calcsize('=QQQ')))
            self.address_state.append((addr_min, addr_max, val))

    def __hash__(self):
        hash_sum = hashlib.sha256()
        hash_sum.update(self.to_bytes())

        return int(hash_sum.hexdigest(), 16)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def to_bytes(self):
        result = bytearray()

        result.extend(struct.pack('N', len(self.register_state)))
        result.extend(self.register_state)

        result.extend(struct.pack("I", len(self.address_state)))
        for (addr_min, addr_max, val) in self.address_state:
            result.extend(struct.pack('=QQQ', addr_min, addr_max, val))

        return result
