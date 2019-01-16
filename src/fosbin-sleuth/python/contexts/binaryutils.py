import subprocess


def find_funcs(binary, target=None):
    location_map = dict()
    readelf_cmd = subprocess.run(['readelf', '-s', binary], capture_output=True)
    lines = readelf_cmd.stdout.split(b'\n')
    for line in lines:
        line = line.decode('utf-8')
        toks = line.split()
        if len(toks) > 4 and toks[3] == "FUNC":
            loc = int(toks[1], 16)
            name = toks[-1]
            if target is None or int(target, 16) == loc:
                location_map[loc] = name
    return location_map
