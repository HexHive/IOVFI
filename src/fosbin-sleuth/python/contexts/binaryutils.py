import subprocess
from .FunctionDescriptor import FunctionDescriptor


def find_funcs(binary, target=None, ignored_funcs=None):
    target_is_name = True
    if target is not None:
        try:
            target = int(target, 16)
            target_is_name = False
        except Exception:
            pass
    location_map = dict()
    readelf_cmd = subprocess.run(['readelf', '-Ws', binary], stdout=subprocess.PIPE)
    lines = readelf_cmd.stdout.split(b'\n')
    for line in lines:
        line = line.decode('utf-8')
        toks = line.split()
        if len(toks) > 4 and toks[3] == "FUNC":
            loc = int(toks[1], 16)
            name = toks[-1]
            if '@' in name:
                name = name[:name.find("@")]

            if ignored_funcs is not None and (name in ignored_funcs or loc in ignored_funcs):
                continue
            if target is None or (not target_is_name and target == loc) or (target_is_name and target == name):
                location_map[loc] = FunctionDescriptor(binary, name, loc)
    return location_map
