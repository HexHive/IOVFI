import logging
import os
import pickle

import numpy
from sklearn import tree, preprocessing

from .FBLogging import logger
from .PinRun import PinMessage, PinRun


class FBDecisionTreeNode:
    def __init__(self, parent=None, left_child=None, right_child=None, identifier=None):
        self.parent = parent
        self.left_child = left_child
        self.right_child = right_child
        self.identifier = identifier

    def is_leaf(self):
        return self.left_child is None and self.right_child is None

    def is_root(self):
        return self.parent is None

    def set_parent(self, parent):
        self.parent = parent

    def set_left_child(self, child):
        self.left_child = child
        child.set_parent(self)

    def set_right_child(self, child):
        self.right_child = child
        child.set_parent(self)

    def get_left_child(self):
        return self.left_child

    def get_right_child(self):
        return self.right_child

    def get_parent(self):
        return self.parent

    def get_identifier(self):
        return self.identifier

    def set_identifier(self, identifier):
        self.identifier = identifier


class FBDecisionTreeInteriorNode(FBDecisionTreeNode):
    def __init__(self, parent=None, iovec=None, coverage=None, left_child=None, right_child=None, identifier=None):
        FBDecisionTreeNode.__init__(self, parent=parent, left_child=left_child, right_child=right_child,
                                    identifier=identifier)
        self.iovec = iovec
        self.coverage = coverage

    def set_iovec(self, iovec):
        self.iovec = iovec

    def get_iovec(self):
        return self.iovec

    def get_coverage(self):
        return self.coverage

    def set_coverage(self, coverage):
        self.coverage = coverage


class FBDecisionTreeLeafNode(FBDecisionTreeNode):
    def __init__(self, equivalence_class=None, confirmation_iovecs=None, parent=None, identifier=None):
        FBDecisionTreeNode.__init__(self, parent=parent, identifier=identifier)
        self.equivalence_class = equivalence_class
        self.confirmation_iovecs = confirmation_iovecs

    def get_equivalence_class(self):
        return self.equivalence_class

    def get_confirmation_iovecs(self):
        return self.confirmation_iovecs

    def set_equivalence_class(self, equivalence_class):
        self.equivalence_class = equivalence_class

    def set_confirmation_iovecs(self, confirmation_iovecs):
        self.confirmation_iovecs = confirmation_iovecs


class FBDecisionTree:
    UNKNOWN_FUNC = -1
    WATCHDOG = 1.0
    MAX_CONFIRM = 1

    def _log(self, msg, level=logging.DEBUG):
        logger.log(level, msg)

    # def _find_dtree_idx(self, index):
    #     if index < 0:
    #         raise ValueError("Invalid dtree index: {}".format(index))
    # 
    #     for base_idx, dtree in self.dtrees.items():
    #         if index < base_idx:
    #             continue
    # 
    #         if index - base_idx < dtree.tree_.node_count:
    #             return base_idx
    #     raise ValueError("Could not find dtree corresponding to index {}".format(index))

    # def _left_child(self, index):
    #     return self._child(index, False)
    # 
    # def _right_child(self, index):
    #     return self._child(index, True)
    # 
    # def _is_leaf(self, index):
    #     if index < 0:
    #         return True
    # 
    #     return self._left_child(index) == self._right_child(index)

    def _attempt_ctx(self, iovec, pin_run, watchdog=WATCHDOG):
        if iovec is None:
            raise AssertionError("No iovec provided")
        elif pin_run is None:
            raise AssertionError("pin_run cannot be None")
        elif not pin_run.is_running():
            raise AssertionError("pin_run is not running")

        ack_msg = pin_run.send_reset_cmd(watchdog)
        if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
            raise AssertionError("Received no ack for set context cmd")
        resp_msg = pin_run.read_response(watchdog)
        if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
            raise AssertionError("Set context command failed")

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

    # def _child(self, index, right_child):
    #     if index < 0:
    #         raise ValueError("Invalid index: {}".format(index))
    #
    #     if index in self.child_dtrees:
    #         return self.child_dtrees[index]
    #
    #     dtree_idx = self._find_dtree_idx(index)
    #     dtree = self.dtrees[dtree_idx]
    #     tree_idx = index - dtree_idx
    #
    #     if right_child:
    #         child_idx = dtree.tree_.children_right[tree_idx]
    #     else:
    #         child_idx = dtree.tree_.children_left[tree_idx]
    #
    #     if child_idx < 0:
    #         return child_idx
    #
    #     return dtree_idx + child_idx

    # def export_graphviz(self, outfile, treeidx=0):
    #     dtree = self.dtrees[treeidx]
    #     tree.export_graphviz(dtree, out_file=outfile, filled=True, rounded=True, special_characters=True,
    #                          node_ids=True, label='none')

    def get_func_descs(self):
        return self.func_descs

    def get_all_equiv_classes(self):
        return self.equivalence_classes

    def get_all_interior_nodes(self):
        for _, node in self.nodes.items():
            if isinstance(node, FBDecisionTreeInteriorNode):
                yield node

    # def get_equiv_classes(self, index):
    #     if index == self.UNKNOWN_FUNC:
    #         return None
    # 
    #     if not self._is_leaf(index):
    #         raise ValueError("Node {} is not a leaf".format(index))
    # 
    #     dtree_idx = self._find_dtree_idx(index)
    #     dtree = self.dtrees[dtree_idx]
    #     tree_idx = index - dtree_idx
    #     equiv_classes = set()
    #     for i in range(len(dtree.tree_.value[tree_idx][0])):
    #         if dtree.tree_.value[tree_idx][0][i]:
    #             hash_sum = dtree.classes_[i]
    #             equiv_classes.add(self.funcDescs[hash_sum])
    # 
    #     return equiv_classes

    def _confirm_leaf(self, func_desc, node, pin_run, max_iovecs=MAX_CONFIRM):
        if max_iovecs <= 0:
            raise RuntimeError("max_iovecs must be greater than zero")

        try:
            self._log("Confirming {}({}) is {}".format(func_desc.name, hex(func_desc.location),
                                                       " ".join([fd.name for fd in node.get_equivalence_class()])))
            if not node.is_leaf():
                raise AssertionError("Node is not a leaf")

            try_count = 0
            for iovec in node.get_confirmation_iovecs():
                self._log("Using iovec {}".format(iovec.hexdigest()))
                try_count += 1
                if not self._attempt_ctx(iovec, pin_run):
                    return False
                if try_count >= max_iovecs:
                    break
            return True
        except Exception as e:
            logger.exception(e)
            raise e

    # def _get_hash(self, index):
    #     base_dtree_index = self._find_dtree_idx(index)
    #     tree_idx = index - base_dtree_index
    #     dtree = self.dtrees[base_dtree_index]
    #     hash = self.labels[base_dtree_index].inverse_transform([dtree.tree_.feature[tree_idx]])[0]
    #     return hash

    # def get_iovec(self, index):
    #     try:
    #         if index < 0:
    #             return None
    #         hash = self._get_hash(index)
    #         base_dtree_index = self._find_dtree_idx(index)
    #         if hash in self.hashMaps[base_dtree_index]:
    #             return self.hashMaps[base_dtree_index][hash]
    #         return None
    #     except:
    #         return None

    def identify(self, func_desc, pin_loc, pintool_loc, loader_loc=None, cwd=os.getcwd(), max_confirm=MAX_CONFIRM,
                 rust_main=None, cmd_log_loc=None, log_loc=None):
        pin_run = PinRun(pin_loc, pintool_loc, func_desc.binary, loader_loc, cwd=cwd, rust_main=rust_main,
                         cmd_log_loc=cmd_log_loc, log_loc=log_loc)

        current_node = self.root

        try:
            while current_node is not None:
                if not pin_run.is_running():
                    pin_run.stop()
                    pin_run.start(timeout=FBDecisionTree.WATCHDOG)
                    if pin_run.rust_main is None:
                        if loader_loc is None:
                            ack_msg = pin_run.send_set_target_cmd(func_desc.location, FBDecisionTree.WATCHDOG)
                        else:
                            ack_msg = pin_run.send_set_target_cmd(func_desc.name, FBDecisionTree.WATCHDOG)
                    else:
                        ack_msg = pin_run.send_set_target_cmd(func_desc.name, FBDecisionTree.WATCHDOG)

                    if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                        raise AssertionError("Could not set target for {}".format(str(func_desc)))
                    resp_msg = pin_run.read_response(FBDecisionTree.WATCHDOG)
                    if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                        raise AssertionError("Could not set target for {}".format(str(func_desc)))

                if current_node.is_leaf():
                    try:
                        if self._confirm_leaf(func_desc, current_node, pin_run, max_confirm):
                            pin_run.stop()
                            return current_node
                        break
                    except RuntimeError as e:
                        # No available hashes, so just mark the identified leaf
                        # as the identified leaf
                        pin_run.stop()
                        return current_node
                    except Exception as e:
                        logger.debug("Error confirming leaf for {}: {}".format(func_desc, e))
                        break

                iovec_accepted = False
                try:
                    logger.debug("Trying iovec {} ({})".format(current_node.identifier, current_node.iovec.hexdigest()))
                    iovec_accepted = self._attempt_ctx(current_node.iovec, pin_run)
                except Exception as e:
                    logger.debug("Error testing iovec for {}: {}".format(str(func_desc), e))

                if iovec_accepted:
                    current_node = current_node.get_right_child()
                else:
                    current_node = current_node.get_left_child()

            pin_run.stop()
            return None
        except Exception as e:
            pin_run.stop()
            raise e

    # def size(self):
    #     size = 0
    #     for dtree in self.dtrees.values():
    #         size += dtree.tree_.node_count
    #
    #     return size

    # def __sizeof__(self):
    #     return self.size()

    def gen_dtree(self, iovec_coverage_location, iovec_hash_map):
        if not os.path.exists(iovec_coverage_location):
            raise FileNotFoundError(iovec_coverage_location)
        if not os.path.exists(iovec_hash_map):
            raise FileNotFoundError(iovec_hash_map)

        self._log("Loading {}...".format(iovec_coverage_location))
        with open(iovec_coverage_location, "rb") as f:
            iovec_coverages = pickle.load(f)
        self._log("done!")

        self._log("Loading {}...".format(iovec_hash_map))
        with open(iovec_hash_map, "rb") as f:
            iovec_hash_map = pickle.load(f)
        self._log("done!")

        labels = preprocessing.LabelEncoder()
        hash_labels = set()
        self._log("Transforming function labels...")
        for hash_sum in iovec_coverages.keys():
            hash_labels.add(hash_sum)
        labels.fit_transform(list(hash_labels))
        self._log("done!")

        funcs_labels = list()
        funcs_features = list()
        added_func_descs = dict()
        accepted_iovecs = dict()

        self._log("Reading in function labels...")
        for hash_sum, coverage_map in iovec_coverages.items():
            idx = labels.transform([hash_sum])[0]
            for func_desc, _ in coverage_map.items():
                func_desc_hash = hash(func_desc)
                self._log("Function {} ({}) accepts IOVec {}".format(func_desc_hash, func_desc.name,
                                                                     hex(hash_sum)))
                if func_desc_hash not in accepted_iovecs:
                    accepted_iovecs[func_desc_hash] = set()
                accepted_iovecs[func_desc_hash].add(hash_sum)

                if func_desc_hash not in added_func_descs:
                    self.func_descs.add(func_desc)
                    added_func_descs[func_desc_hash] = func_desc
                    funcs_labels.append(func_desc_hash)
                    funcs_features.append(numpy.zeros(len(labels.classes_), dtype=bool))
                func_feature = funcs_features[funcs_labels.index(func_desc_hash)]
                func_feature[idx] = True
        self._log("done!")

        dtree = tree.DecisionTreeClassifier()
        self._log("Creating decision tree...")
        dtree.fit(funcs_features, funcs_labels)
        self.nodes = dict()
        path_iovec_hashes = set()
        for index in range(0, dtree.tree_.node_count):
            right_child = dtree.tree_.children_right[index]
            left_child = dtree.tree_.children_left[index]
            if left_child == right_child:
                self.nodes[index] = FBDecisionTreeLeafNode(identifier=index)
            else:
                iovec_hash = labels.inverse_transform([dtree.tree_.feature[index]])[0]
                path_iovec_hashes.add(iovec_hash)
                iovec = iovec_hash_map[iovec_hash]
                self._log("Adding IOVec {} to path".format(iovec))
                self.nodes[index] = FBDecisionTreeInteriorNode(iovec=iovec, coverage=iovec_coverages[iovec_hash],
                                                               identifier=index)

        for index in range(0, dtree.tree_.node_count):
            right_child_idx = dtree.tree_.children_right[index]
            left_child_idx = dtree.tree_.children_left[index]
            current_node = self.nodes[index]
            if index == 0:
                self.root = current_node

            if right_child_idx != left_child_idx:
                right_child = self.nodes[right_child_idx]
                left_child = self.nodes[left_child_idx]
                current_node.set_left_child(left_child)
                current_node.set_right_child(right_child)
            else:
                # We are a leaf, the parent member will be set elsewhere
                equivalence_class = list()
                confirmation_iovec_hashes = set()
                for i in range(len(dtree.tree_.value[index][0])):
                    if dtree.tree_.value[index][0][i]:
                        hash_sum = dtree.classes_[i]
                        if hash_sum in added_func_descs:
                            func_desc_to_add = added_func_descs[hash_sum]
                            self._log(
                                "Adding func desc {} to node {}".format(func_desc_to_add, current_node.identifier))
                            equivalence_class.append(func_desc_to_add)
                            for iovec_hash in accepted_iovecs[hash_sum]:
                                confirmation_iovec_hashes.add(iovec_hash)
                        else:
                            self._log("Func desc {} is not in added_func_descs".format(hash_sum))
                            continue

                current_node.set_equivalence_class(equivalence_class)
                self.equivalence_classes.append(equivalence_class)

                confirmation_iovecs = list()
                for iovec_hash in confirmation_iovec_hashes:
                    if iovec_hash not in path_iovec_hashes:
                        self._log(
                            "Adding iovec {} to node {}".format(iovec_hash_map[iovec_hash], current_node.identifier))
                        confirmation_iovecs.append(iovec_hash_map[iovec_hash])
                current_node.set_confirmation_iovecs(confirmation_iovecs)
        self._log("done!")

    def __init__(self, iovec_coverage_location, iovec_hash_map):
        self.root = None
        self.func_descs = set()
        self.nodes = dict()
        self.equivalence_classes = list()
        self.gen_dtree(iovec_coverage_location, iovec_hash_map)
