import argparse
import os
import sys


def import_applications(ghidraPath, binaries, baseDir):
    baseDir = os.path.abspath(baseDir)
    project_dir = os.path.join(os.path.abspath(os.path.curdir), "tempProject")
    if not os.path.exists(project_dir):
        os.makedirs(project_dir, exist_ok=True)

    for bin in binaries:
        importPath = os.path.join("TempProject", bin)
        binPath = os.path.join(baseDir, bin)
        cmd = "{} {} {} -import {} -overwrite".format(ghidraPath, project_dir,
                                                      importPath, binPath)
        print("Running {}...".format(cmd), end="")
        sys.stdout.flush()
        os.system(cmd)
        print("done!")


def main():
    parser = argparse.ArgumentParser(description="Imports all applications "
                                                 "into Ghidra")
    parser.add_argument('-g', '--ghidraPath', required=True)
    parser.add_argument('binaries', metavar='B', nargs='+')
    parser.add_argument('-b', '--baseDir', required=True)
    args = parser.parse_args()

    import_applications(args.ghidraPath, args.binaries, args.baseDir)


if __name__ == "__main__":
    main()
