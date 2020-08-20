import argparse
import os
import sys


def import_applications(ghidraPath, binaries):
    projectDir = os.path.join(os.path.abspath(os.path.curdir), "tempProject")
    if not os.path.exists(projectDir):
        os.makedirs(projectDir, exist_ok=True)

    for bin in binaries:
        importPath = os.path.join("TempProject", bin)
        cmd = "{} {} {} -scriptPath $PWD -postScript " \
              "BinExportScript.java -process {} -noanalysis".format(ghidraPath,
                                                                    projectDir,
                                                                    importPath,
                                                                    os.path.basename(
                                                                        importPath))
        print("Running {}...".format(cmd), end="")
        sys.stdout.flush()
        os.system(cmd)
        print("done!")


def main():
    parser = argparse.ArgumentParser(description="Imports all applications "
                                                 "into Ghidra")
    parser.add_argument('-g', '--ghidraPath', required=True)
    parser.add_argument('binaries', metavar='B', nargs='+')
    args = parser.parse_args()

    import_applications(args.ghidraPath, args.binaries)


if __name__ == "__main__":
    main()
