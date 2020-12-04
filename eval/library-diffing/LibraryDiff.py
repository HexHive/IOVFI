import re
import subprocess
import os
import io


def get_git_diffs(version1, version2):
    stat_regex_str = "(\d*)\s+(\d*)\s+(\S+)"
    stat_regex = re.compile(stat_regex_str)

    total_adds = 0
    total_dels = 0

    cmd = ['git', 'diff', version1, version2, '--numstat']
    print("Running {} in {}".format(" ".join(cmd), os.getcwd()))
    diff_result = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    for line in io.TextIOWrapper(diff_result.stdout, encoding="utf-8"):
        line = line.rstrip()
        stat_match = stat_regex.match(line)
        if stat_match:
            file_name = stat_match.group(3)
            _, extension = os.path.splitext(file_name)
            if extension in (".c", ".h"):
                total_adds += int(stat_match.group(1))
                total_dels += int(stat_match.group(2))

    return total_adds, total_dels


def main():
    versions = ['v1.2.7', 'v1.2.7.1', 'v1.2.7.2', 'v1.2.7.3', 'v1.2.8',
                'v1.2.9', 'v1.2.10', 'v1.2.11']

    os.chdir('/home/derrick/code/zlib')
    for version1 in versions:
        for version2 in versions:
            print("{} {} {}".format(version1, version2, get_git_diffs(version1,
                                                              version2)))


if __name__ == "__main__":
    main()