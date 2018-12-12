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

        for func in r2.cmdj("aflj"):
            func_count += 1
            try:
                # pin -t fosbin-zergling.so -target 0xCAFEBABE -out app_foo.bin -- app
                cmd = [os.path.join(sys.argv[1], "pin"), "-t", sys.argv[2], "-target", hex(func['offset']),
                       "-out", "{}_{}.bin".format(os.path.basename(app)[0:5], func['name']),
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
