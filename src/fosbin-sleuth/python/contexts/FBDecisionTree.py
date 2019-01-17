import os
import pickle
import sys
from sklearn import tree, preprocessing
import numpy
import subprocess
from contexts import binaryutils


class FBDecisionTree:
    UNKNOWN_FUNC = -1
    WATCHDOG_MS = 5000

    def _log(self, msg, print_output=True, end='\n'):
        if print_output:
            print(msg, end=end)
            sys.stdout.flush()

    def _find_dtree_idx(self, index):
        if index < 0:
            raise ValueError("Invalid dtree index: {}".format(index))

        for base_idx, dtree in self.dtrees.items():
            if index < base_idx:
                continue

            if index - base_idx < dtree.tree_.node_count:
                return base_idx
        raise ValueError("Could not find dtree corresponding to index {}".format(index))

    def _left_child(self, index):
        return self._child(index, False)

    def _right_child(self, index):
        return self._child(index, True)

    def _is_leaf(self, index):
        if index < 0:
            return True

        return self._left_child(index) == self._right_child(index)

    def _attempt_ctx(self, iovec, pindir, tool, loc, name, binary, hash, verbose=False, watchdog=WATCHDOG_MS):
        if iovec is None:
            raise AssertionError("No iovec provided")

        fullPath = os.path.abspath(os.path.join(binaryutils.WORK_DIR, binaryutils.CTX_FILENAME))
        if not os.path.exists(binaryutils.WORK_DIR):
            os.mkdir(binaryutils.WORK_DIR)

        ctx_file = open(fullPath, "wb+")
        iovec.write_bin(ctx_file)
        ctx_file.close()
        cmd = [os.path.abspath(os.path.join(pindir, "pin")), "-t", os.path.abspath(tool), "-fuzz-count", "0",
               "-target", hex(loc), "-out", os.path.basename(binary) + "." + name + ".log", "-watchdog", str(watchdog),
               "-contexts", fullPath, "--", os.path.abspath(binary)]

        accepted = False
        devnull = open(os.devnull, "w")
        try:
            self._log("Testing {}.{} ({}) with hash {}...".format(os.path.basename(binary), name, hex(loc), hash),
                      verbose, end='')
            sys.stdout.flush()
            fuzz_cmd = subprocess.run(cmd, stdout=devnull, stderr=subprocess.STDOUT, timeout=watchdog / 1000 + 1, \
                                      cwd=os.path.abspath(binaryutils.WORK_DIR))
            accepted = (fuzz_cmd.returncode == 0)

            if accepted:
                return True
            else:
                return False
        except subprocess.TimeoutExpired:
            self._log("Timeout", verbose)
            return False
        except Exception as e:
            self._log("General exception: {}".format(e), verbose)
            return False
        finally:
            if not accepted:
                self._log("failed", verbose)
            else:
                self._log("accepted!", verbose)

            if os.path.exists(fullPath):
                os.unlink(fullPath)

    def _child(self, index, right_child):
        if index < 0:
            raise ValueError("Invalid index: {}".format(index))

        if index in self.child_dtrees:
            return self.child_dtrees[index]

        dtree_idx = self._find_dtree_idx(index)
        dtree = self.dtrees[dtree_idx]
        tree_idx = index - dtree_idx

        if right_child:
            child_idx = dtree.tree_.children_right[tree_idx]
        else:
            child_idx = dtree.tree_.children_left[tree_idx]

        if child_idx < 0:
            return child_idx

        return dtree_idx + child_idx

    def export_graphviz(self, outfile, treeidx=0):
        dtree = self.dtrees[treeidx]
        tree.export_graphviz(dtree, out_file=outfile, filled=True, rounded=True, special_characters=True)

    def _get_equiv_classes(self, index):
        if index == self.UNKNOWN_FUNC:
            return {"UNKNOWN"}

        if not self._is_leaf(index):
            raise ValueError("Node {} is not a leaf".format(index))

        dtree_idx = self._find_dtree_idx(index)
        dtree = self.dtrees[dtree_idx]
        tree_idx = index - dtree_idx
        equiv_classes = set()
        for i in range(len(dtree.tree_.value[tree_idx][0])):
            if dtree.tree_.value[tree_idx][0][i]:
                equiv_classes.add(dtree.classes_[i])

    def _confirm_leaf(self, location, pindir, tool, binary, name, index):
        if not self._is_leaf(index):
            raise AssertionError("{} is not a leaf".format(index))

        dtree_base_idx = self._find_dtree_idx(index)
        dtree = self.dtrees[dtree_base_idx]
        descMap = self.descMaps[dtree_base_idx]
        hashMap = self.hashMaps[dtree_base_idx]
        labels = self.labels[dtree_base_idx]

        possible_equivs = self._get_equiv_classes(index)

        available_hashes = set()
        for hash, accepting_funcs in descMap.items():
            for possible_equiv in possible_equivs:
                if possible_equiv in accepting_funcs:
                    available_hashes.add(hash)

        used_hashes = labels.inverse_transform(dtree.tree_.features)
        for used_hash in used_hashes:
            available_hashes.remove(used_hash)

        if len(available_hashes) == 0:
            raise AssertionError("There are no available hashes to confirm {}({}) is {}".format(hex(location),
                                                                                                name, possible_equivs))
        hash = available_hashes[0]
        iovec = hashMap[hash]
        return self._attempt_ctx(iovec, pindir, tool, location, name, binary, hash)

    def _get_hash(self, index):
        base_dtree_index = self._find_dtree_idx(index)
        tree_idx = index - base_dtree_index
        dtree = self.dtrees[base_dtree_index]
        hash = self.labels[base_dtree_index].inverse_transform([dtree.tree_.feature[tree_idx]])[0]
        return hash

    def _get_iovec(self, index):
        hash = self._get_hash(index)
        base_dtree_index = self._find_dtree_idx(index)
        return self.hashMaps[base_dtree_index][hash]

    def identify(self, location, pindir, tool, binary, name=None):
        if name is None:
            name = hex(location)

        idx = 0
        while idx < self.size():
            if self._is_leaf(idx):
                if self._confirm_leaf(location, pindir, tool, binary, name, idx):
                    return self._get_equiv_classes(idx)
                break

            iovec = self._get_iovec(idx)
            if self._attempt_ctx(iovec, pindir, tool, location, name, binary, hash):
                idx = self._right_child(idx)
            else:
                idx = self._left_child(idx)

        return self._get_equiv_classes(self.UNKNOWN_FUNC)

    def size(self):
        size = 0
        for dtree in self.dtrees.values():
            size += dtree.tree_.node_count

        return size

    def __sizeof__(self):
        return self.size()

    def add_dtree(self, descLoc, hashMapLoc, verbose=False):
        if not os.path.exists(descLoc):
            raise FileNotFoundError(descLoc)
        if not os.path.exists(hashMapLoc):
            raise FileNotFoundError(hashMapLoc)

        base_idx = 0
        for dtree in self.dtrees.items():
            base_idx += dtree.tree_.node_count
        self._log("base_idx = {}".format(base_idx), verbose)

        self._log("Loading {}...".format(descLoc), verbose, '')
        with open(descLoc, "rb") as descFile:
            self.descMaps[base_idx] = pickle.load(descFile)
        self._log("done!", verbose)

        self._log("Loading {}...".format(hashMapLoc), verbose, '')
        with open(hashMapLoc, "rb") as hashMapFile:
            self.hashMaps[base_idx] = pickle.load(hashMapFile)
        self._log("done!", verbose)

        labels = preprocessing.LabelEncoder()
        hash_labels = set()
        self._log("Transforming function labels...", verbose, '')
        for hashes in self.descMaps[base_idx].keys():
            hash_labels.add(hashes)
        labels.fit_transform(list(hash_labels))
        self.labels[base_idx] = labels
        self._log("done!", verbose)

        funcs_labels = list()
        funcs_features = list()

        self._log("Reading in function labels...", verbose, '')
        for key, funcs in self.descMaps[base_idx].items():
            idx = self.labels[base_idx].transform([key])[0]
            for func in funcs:
                if func not in funcs_labels:
                    funcs_labels.append(func)
                    funcs_features.append(numpy.zeros(len(self.labels[base_idx].classes_), dtype=bool))
                func_feature = funcs_features[funcs_labels.index(func)]
                func_feature[idx] = True
        self._log("done!", verbose)

        dtree = tree.DecisionTreeClassifier()
        self._log("Creating decision tree...", verbose, '')
        dtree.fit(funcs_features, funcs_labels)
        self.dtrees[base_idx] = dtree
        self._log("done!", verbose)

    def __init__(self, descLoc, hashMapLoc, verbose=False):
        # Map of base index to dtree
        self.dtrees = dict()
        # Map of Whole Tree Index to Child Subtree Whole Tree Index
        self.child_dtrees = dict()
        # Map of Whole Tree Index to Corresponding Labels
        self.labels = dict()
        # Map of Whole Tree Index to Corresponding Descriptors
        self.descMaps = dict()
        # Map of Whole Tree Index to Corresponding Hash Maps
        self.hashMaps = dict()

        self.add_dtree(descLoc, hashMapLoc, verbose)
