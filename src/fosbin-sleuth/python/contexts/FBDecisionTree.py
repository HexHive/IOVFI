import os
import pickle
from sklearn import tree, preprocessing
import numpy
import logging
from .FBLogging import logger
from .PinRun import PinMessage, PinRun


class FBDecisionTree:
    UNKNOWN_FUNC = -1
    WATCHDOG = 1.0

    def _log(self, msg, level=logging.INFO):
        logger.log(level, msg)

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

    def _attempt_ctx(self, iovec, pin_run, watchdog=WATCHDOG):
        if iovec is None:
            raise AssertionError("No iovec provided")
        elif pin_run is None:
            raise AssertionError("pin_run cannot be None")
        elif not pin_run.is_running():
            raise AssertionError("pin_run is not running")

        ack_msg = pin_run.send_set_ctx_cmd(iovec, watchdog)
        if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
            raise AssertionError("Received no ack for set context cmd")
        resp_msg = pin_run.read_response(watchdog)
        if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
            raise AssertionError("Set context command failed")

        ack_msg = pin_run.send_execute_cmd(watchdog)
        if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
            raise AssertionError("Received no ack for execute cmd")
        resp_msg = pin_run.read_response(watchdog)
        if resp_msg is None:
            raise AssertionError("Execute command did not return")
        return resp_msg.msgtype == PinMessage.ZMSG_OK

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

    def get_equiv_classes(self, index):
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
                hash_sum = dtree.classes_[i]
                equiv_classes.add(self.funcDescs[hash_sum])

        return equiv_classes

    def _confirm_leaf(self, location, name, index, pin_run):
        self._log("Confirming {}({}) is {}".format(name, hex(location),
                                                   self.get_equiv_classes(index)))
        if not self._is_leaf(index):
            raise AssertionError("{} is not a leaf".format(index))

        dtree_base_idx = self._find_dtree_idx(index)
        dtree = self.dtrees[dtree_base_idx]
        descMap = self.descMaps[dtree_base_idx]
        hashMap = self.hashMaps[dtree_base_idx]
        labels = self.labels[dtree_base_idx]

        possible_equivs = self.get_equiv_classes(index)

        available_hashes = list()
        for hash_sum, accepting_funcs in descMap.items():
            for possible_equiv in possible_equivs:
                if possible_equiv in accepting_funcs:
                    available_hashes.append(hash_sum)

        used_labels = set()
        for feature in dtree.tree_.feature:
            if feature > 0:
                used_labels.add(feature)
        used_hashes = labels.inverse_transform(list(used_labels))
        for used_hash in used_hashes:
            if used_hash in available_hashes:
                available_hashes.remove(used_hash)

        if len(available_hashes) == 0:
            raise AssertionError("There are no available hashes to confirm {}({}) is {}".format(hex(location),
                                                                                                name, possible_equivs))
        hash_sum = available_hashes[0]
        iovec = hashMap[hash_sum]
        return self._attempt_ctx(iovec, pin_run)

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

    def identify(self, func_desc, pin_loc, pintool_loc, loader_loc=None, cwd=os.getcwd()):
        pin_run = PinRun(pin_loc, pintool_loc, func_desc.binary, loader_loc, cwd=cwd)

        idx = 0
        try:
            while idx < self.size():
                if not pin_run.is_running():
                    pin_run.stop()
                    pin_run.start(timeout=FBDecisionTree.WATCHDOG)
                    ack_msg = pin_run.send_set_target_cmd(func_desc.location, FBDecisionTree.WATCHDOG)
                    if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                        raise AssertionError("Could not set target for {}".format(str(func_desc)))
                    resp_msg = pin_run.read_response(FBDecisionTree.WATCHDOG)
                    if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                        raise AssertionError("Could not set target for {}".format(str(func_desc)))

                if self._is_leaf(idx):
                    try:
                        if self._confirm_leaf(func_desc.location, idx):
                            pin_run.stop()
                            return idx
                        break
                    except Exception as e:
                        logger.exception("Error confirming leaf for {}: {}".format(func_desc, e))
                        break

                iovec = self._get_iovec(idx)
                iovec_accepted = False
                try:
                    iovec_accepted = self._attempt_ctx(iovec, pin_run)
                except Exception as e:
                    logger.exception("Error testing iovec for {}: {}".format(str(func_desc), e))

                if iovec_accepted:
                    idx = self._right_child(idx)
                else:
                    idx = self._left_child(idx)

            pin_run.stop()
            return self.UNKNOWN_FUNC
        except Exception as e:
            pin_run.stop()
            raise e

    def size(self):
        size = 0
        for dtree in self.dtrees.values():
            size += dtree.tree_.node_count

        return size

    def __sizeof__(self):
        return self.size()

    def add_dtree(self, descLoc, hashMapLoc):
        if not os.path.exists(descLoc):
            raise FileNotFoundError(descLoc)
        if not os.path.exists(hashMapLoc):
            raise FileNotFoundError(hashMapLoc)

        base_idx = 0
        for dtree in self.dtrees.items():
            base_idx += dtree.tree_.node_count
        self._log("base_idx = {}".format(base_idx))

        msg = "Loading {}...".format(descLoc)
        with open(descLoc, "rb") as descFile:
            self.descMaps[base_idx] = pickle.load(descFile)
        for key, funcDescs in self.descMaps[base_idx].items():
            for funcDesc in funcDescs:
                self.funcDescs[hash(funcDesc)] = funcDesc
        self._log(msg + "done!")

        msg = "Loading {}...".format(hashMapLoc)
        with open(hashMapLoc, "rb") as hashMapFile:
            self.hashMaps[base_idx] = pickle.load(hashMapFile)
        self._log(msg + "done!")

        labels = preprocessing.LabelEncoder()
        hash_labels = set()
        msg = "Transforming function labels..."
        for hashes in self.descMaps[base_idx].keys():
            hash_labels.add(hashes)
        labels.fit_transform(list(hash_labels))
        self.labels[base_idx] = labels
        self._log(msg + "done!")

        funcs_labels = list()
        funcs_features = list()
        added_func_hashes = set()

        msg = "Reading in function labels..."
        count = 0
        for key, funcs in self.descMaps[base_idx].items():
            idx = self.labels[base_idx].transform([key])[0]
            count += 1
            for func in funcs:
                hashsum = hash(func)
                if hashsum not in added_func_hashes:
                    added_func_hashes.add(hashsum)
                    funcs_labels.append(hashsum)
                    funcs_features.append(numpy.zeros(len(self.labels[base_idx].classes_), dtype=bool))
                func_feature = funcs_features[funcs_labels.index(hashsum)]
                func_feature[idx] = True
        self._log(msg + "done!")

        dtree = tree.DecisionTreeClassifier()
        msg = "Creating decision tree..."
        dtree.fit(funcs_features, funcs_labels)
        self.dtrees[base_idx] = dtree
        self._log(msg + "done!")

    def __init__(self, descLoc, hashMapLoc):
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
        # Map of all function hashes to FunctionDescriptors
        self.funcDescs = dict()

        self.add_dtree(descLoc, hashMapLoc)
