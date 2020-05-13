import argparse
import os
import pathlib
import subprocess
import sys
import time

import yaml


class Directory:
    def __init__(self, path, short_name):
        self.path = path
        self.short_name = short_name


class Experiment:
    def __init__(self, id, timeout, trees, eval_dirs, eval_bins, base_dir, se_dir, valgrind):
        if not os.path.exists(valgrind):
            raise FileNotFoundError(valgrind)
        if trees is None or len(trees) == 0:
            raise AssertionError("Trees cannot be empty")
        if base_dir is None or len(base_dir) == 0:
            base_dir = os.curdir
        if self.id is None or len(self.id) == 0:
            raise AssertionError("ID cannot be empty")
        if se_dir is None or not os.path.exists(se_dir):
            raise AssertionError("Could not find SE dir")
        if not os.path.exists(os.path.join(se_dir, "src", "software-ethology", "fuzz-applications.py")):
            raise AssertionError("Missing fuzz_applications.py")

        self.valgrind = os.path.abspath(valgrind)
        self.base_dir = base_dir
        self.eval_dirs = eval_dirs
        self.eval_bins = eval_bins
        self.id = id
        self.se_dir = os.path.abspath(se_dir)
        self.start_time = None
        self.ignore = None
        self.executed_commands = 0
        self.timeout = timeout

    def init(self):
        self.ignore = os.path.join(self.se_dir, "tests", "ignored.txt")
        self.executed_commands = 0
        self.start_time = None

    def log(self, msg):
        if self.start_time is None:
            self.start_time = time.time()
        duration = int(time.time() - self.start_time)
        print("[{}] {}".format(duration, msg))
        sys.stdout.flush()

    def execute_command(self, command, dry_run):
        cmd_tokens = command.split()
        self.log("Executing {}".format(cmd_tokens))
        self.executed_commands += 1
        result = True
        if not dry_run:
            try:
                if not os.path.exists(os.path.join(self.base_dir, "cmds")):
                    os.mkdir(os.path.join(self.base_dir, "cmds"))
                out_path = os.path.join(self.base_dir, "cmds", "{}.{}.out".format(self.id, self.executed_commands))
                err_path = os.path.join(self.base_dir, "cmds", "{}.{}.err".format(self.id, self.executed_commands))
                out_file = open(out_path, "w")
                err_file = open(err_path, "w")
                subprocess.run(cmd_tokens, check=True, stdout=out_file, stderr=err_file)
            except Exception as e:
                self.log("ERROR: {}".format(str(e)))
                result = False
            finally:
                out_file.close()
                err_file.close()
        if result:
            self.log("Command Complete")

    def create_directory(self, dir_path, dry_run=True):
        path = pathlib.Path(dir_path)
        if not path.exists():
            self.log("Creating {}".format(dir_path))
            if not dry_run:
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    if not path.exists():
                        raise AssertionError("{} wasn't created".format(dir_path))
                except Exception as e:
                    self.log("ERROR: Failed to create {}: {}".format(dir_path, str(e)))
        else:
            self.log("{} exists...skipping".format(dir_path))

    def change_directory(self, dir, dry_run=True):
        self.create_directory(dir, dry_run)
        self.log("Changing directory to {} from {}".format(dir, os.getcwd()))
        if not dry_run:
            if not os.path.isdir(dir):
                self.log("ERROR: {} is not a directory".format(dir))
                return
            if os.path.exists(dir):
                os.chdir(dir)
            else:
                self.log("ERROR: {} does not exist".format(dir))
        self.log("Current directory: {}".format(os.getcwd()))

    def create_tree(self, tree, dry_run=True):
        if not os.path.exists(tree['dest']):
            self.log("Creating tree {} from source {}".format(tree['dest'], tree['src_bin']))
            if not dry_run and not os.path.exists(tree['src_bin']):
                raise AssertionError("Tree source {} does not exist".format(tree['src_bin']))
            cmd = "python3 {} -valgrind {} -bin {} -ignore {} -t {} -timeout {}".format(
                os.path.join(self.se_dir, "src", "software-ethology", "python", "fuzz-applications.py"), self.valgrind,
                tree['src_bin'], self.ignore, tree['dest'], self.timeout)
            self.execute_command(cmd, dry_run=dry_run)
        else:
            self.log("{} already exists...skipping".format(tree['dest']))

    def get_eval_dir(self, src_binary, tree_path, eval_dir):
        return os.path.abspath(
            os.path.join(os.path.dirname(tree_path), eval_dir.short_name, os.path.basename(src_binary)))

    def identify_functions(self, tree_path, binary_path, guess_path, dry_run=True):
        self.change_directory(os.path.dirname(guess_path), dry_run)
        cmd = "python3 {} -valgrind {} -b {} -ignore {} -t {} -guesses {} -timeout {}".format(
            os.path.join(self.se_dir, "src", "software-ethology", "python", "IdentifyFunction.py"), self.valgrind,
            os.path.abspath(binary_path), self.ignore, os.path.abspath(tree_path), guess_path, self.timeout)
        self.execute_command(cmd, dry_run=dry_run)

    def compute_accuracy(self, tree_path, guess_path, output_path, dry_run=True):
        self.change_directory(os.path.dirname(guess_path), dry_run)
        with open('guesses.txt', 'w') as f:
            f.write(guess_path)

        cmd = "python3 {} -t {} -o {}".format(
            os.path.join(self.se_dir, "src", "software-ethology", "python", "ComputeAccuracy.py"),
            os.path.abspath(tree_path), output_path)
        self.execute_command(cmd, dry_run)

    def run(self, dry_run=True):
        orig_dir = os.curdir
        self.init()
        self.start_time = time.time()
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)
        orig_sysout = sys.stdout
        orig_syserr = sys.stderr
        log_path = os.path.abspath(os.path.join(self.base_dir, "{}.log".format(self.id)))
        err_path = os.path.abspath(os.path.join(self.base_dir, "{}.err".format(self.id)))
        self.log('Logging to {}'.format(log_path))
        log = open(log_path, 'w')
        err = open(err_path, 'w')
        sys.stdout = log
        sys.stderr = err
        try:
            for tree in self.trees:
                self.log("Starting evaluation of {}".format(tree['dest']))
                self.change_directory(os.path.dirname(tree['dest']), dry_run=dry_run)
                self.create_tree(tree, dry_run=dry_run)
                if dry_run or os.path.exists(tree['dest']):
                    for eval_dir in self.eval_dirs:
                        for binary_path in self.eval_bins:
                            src_bin = os.path.join(eval_dir.path, binary_path)
                            guess_path = os.path.join(self.get_eval_dir(src_bin, tree['dest'], eval_dir), 'guesses.bin')
                            self.identify_functions(tree_path=tree['dest'], binary_path=src_bin, guess_path=guess_path,
                                                    dry_run=dry_run)
                            if dry_run or os.path.exists(guess_path):
                                self.compute_accuracy(tree['dest'], guess_path,
                                                      os.path.join(os.path.dirname(tree['dest']), eval_dir.short_name,
                                                                   "accuracy.bin"),
                                                      dry_run)
                            else:
                                self.log("ERROR: Identification failed for {}".format(self.get_eval_dir(src_bin)))
                else:
                    self.log("ERROR: Tree creation failed for {}".format(tree['dest']))
        finally:
            sys.stdout = orig_sysout
            sys.stderr = orig_syserr
            log.close()
            err.close()


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument('-experiment', '-e', help='/path/to/experiment.yaml', required=True)
    parser.add_argument('-dry', type=str2bool, nargs='?', const=True, default=True, help="Dry run")

    args = parser.parse_args()

    with open(args.experiment, 'r') as f:
        experiment = yaml.load(f, Loader=yaml.FullLoader)

    experiment.run(dry_run=args.dry)


if __name__ == "__main__":
    main()
