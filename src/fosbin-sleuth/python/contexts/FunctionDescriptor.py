import os


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

    def __hash__(self):
        if self.name is not None:
            return hash((self.binary, self.name))
        else:
            return hash((self.binary, self.location))
