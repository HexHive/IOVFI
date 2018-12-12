#!/usr/bin/python3

import r2pipe
import os
import sys
import subprocess


def usage():
    print("{} /path/to/pin /path/to/fosbin-zergling.so /path/to/application [/path/to/application...]".format(
        "fuzz-applications.py"))
    sys.exit(1)


def main():
    if len(sys.argv) < 4:
        usage()

    if os.path.exists("fuzz-results.bin"):
        os.rename("fuzz-results.bin", "fuzz-results.bin.orig")

    env_vars = dict()
    for app in sys.argv[3:]:
        r2 = r2pipe.open(app)
        r2.cmd('aaa')
        func_count = 0
        text_section = None
        for s in r2.cmdj("iSj"):
            if s['name'] == ".text":
                text_section = s
                break

        for func in r2.cmdj("aflj"):
            if func['offset'] >= text_section['vaddr'] and func['offset'] <= \
                    text_section['vaddr'] + text_section['size']:
                func_count += 1
                try:
                    # pin -t fosbin-zergling.so -target 0xCAFEBABE -out app_foo.bin -- app
                    cmd = [sys.argv[1], "-t", sys.argv[2], "-target", hex(func['offset']),
                           "-out", "{}_{}.bin".format(app, func['name']),
                           "--", app]
                    print("Running {}".format(" ".join(cmd)))
                    subprocess.run(cmd, env=env_vars, timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                except Exception as e:
                    print("Error for {}:{} : {}".format(app, func['name'], e), file=sys.stderr)
                    continue

                print("Finished {}".format(func['name']))
                if os.path.exists("fuzz-results.bin"):
                    os.rename("fuzz-results.bin", "{}_{}.bin".format(app, func['name']))

        print("{} has {} functions".format(app, func_count))
        r2.quit()

if __name__ == "__main__":
    main()
