import subprocess

WORK_DIR = "_work"
CTX_FILENAME = "tmp.ctx"
LOGGER_NAME = "fb-logger"


def find_funcs(binary, target=None):
    target_is_name = True
    if target is not None:
        try:
            target = int(target, 16)
            target_is_name = False
        except Exception:
            pass
    location_map = dict()
    readelf_cmd = subprocess.run(['readelf', '-s', binary], stdout=subprocess.PIPE)
    lines = readelf_cmd.stdout.split(b'\n')
    for line in lines:
        line = line.decode('utf-8')
        toks = line.split()
        if len(toks) > 4 and toks[3] == "FUNC":
            loc = int(toks[1], 16)
            name = toks[-1]
            if target is None or (not target_is_name and target == loc) or (target_is_name and target == name):
                location_map[loc] = name
    return location_map
