import hashlib
import os
import struct


class FunctionDescriptor:
    def __init__(self, binary, name, location):
        if binary is None:
            raise ValueError("Binary must be provided")
        if name is None and location is None:
            raise ValueError("A name or a location must be provided")

        self.binary = os.path.abspath(binary)
        self.name = name
        self.location = location

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __str__(self):
        result = os.path.basename(self.binary)
        if self.name is not None:
            result += ".{}".format(self.name)
        else:
            result += ".0x{}".format(hex(self.location))
        return result

    def _get_hash_obj(self):
        m = hashlib.sha256()
        m.update(self.binary.encode('utf-8'))
        if self.name is None:
            m.update(struct.pack('P', self.location))
        else:
            m.update(self.name.encode('utf-8'))
        return m

    def hash(self):
        return self._get_hash_obj().digest()

    def __hash__(self):
        return int(self._get_hash_obj().hexdigest(), 16)
