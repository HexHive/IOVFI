import logging
import os
import pickle

import numpy
from sklearn import tree, preprocessing

from .FBLogging import logger
from .SEGrindRun import SEMsgType, SEGrindRun


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

    def _attempt_ctx(self, iovec, segrind_run):
        if iovec is None:
            raise AssertionError("No iovec provided")
        elif segrind_run is None:
            raise AssertionError("pin_run cannot be None")
        elif not segrind_run.is_running():
            raise AssertionError("pin_run is not running")

        # ack_msg = segrind_run.send_reset_cmd(watchdog)
        # if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
        #     raise AssertionError("Received no ack for set context cmd")
        # resp_msg = segrind_run.read_response(watchdog)
        # if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
        #     raise AssertionError("Set context command failed")

        ack_msg = segrind_run.send_set_ctx_cmd(iovec)
        if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
            raise AssertionError("Received no ack for set context cmd")
        resp_msg = segrind_run.read_response()
        if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
            raise AssertionError("Set context command failed")

        ack_msg = segrind_run.send_execute_cmd()
        if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
            raise AssertionError("Received no ack for execute cmd")
        resp_msg = segrind_run.read_response()
        if resp_msg is None:
            raise AssertionError("Execute command did not return")
        if resp_msg.msgtype == SEMsgType.SEMSG_OK:
            # return True, resp_msg.get_coverage()
            return True, None
        else:
            return False, None

    def get_func_descs(self):
        return self.func_descs

    def get_all_equiv_classes(self):
        return self.equivalence_classes

    def get_all_interior_nodes(self):
        for _, node in self.nodes.items():
            if isinstance(node, FBDecisionTreeInteriorNode):
                yield node

    def _confirm_leaf(self, func_desc, node, segrind_run, max_iovecs=MAX_CONFIRM):
        if max_iovecs <= 0:
            raise RuntimeError("max_iovecs must be greater than zero")

        try:
            self._log("Confirming {}({}) is {}".format(func_desc.name, hex(func_desc.location),
                                                       " ".join([fd.name for fd in node.get_equivalence_class()])))
            if not node.is_leaf():
                raise AssertionError("Node is not a leaf")

            try_count = 0
            # coverages = list()
            confirmation_iovecs = node.get_confirmation_iovecs()
            if len(confirmation_iovecs) == 0:
                raise AssertionError("No confirmation IOVecs")

            for iovec in node.get_confirmation_iovecs():
                self._log("Using iovec {}".format(iovec.hexdigest()))
                try_count += 1
                accepted, _ = self._attempt_ctx(iovec, segrind_run)
                if not accepted:
                    return False, None
                if try_count >= max_iovecs:
                    break
                # coverages.append(coverage)
            return True, None
        except Exception as e:
            return False, None

    def identify(self, func_desc, valgrind_loc, timeout, cwd=os.getcwd(), max_confirm=MAX_CONFIRM,
                 cmd_log_loc=None, log_loc=None):
        segrind_run = SEGrindRun(valgrind_loc, func_desc.binary, timeout=timeout, cwd=cwd, valgrind_log_loc=log_loc,
                                 run_log_loc=cmd_log_loc)

        current_node = self.root

        coverages = list()
        try:
            while current_node is not None:
                if not segrind_run.is_running():
                    segrind_run.stop()
                    segrind_run.start()
                    ack_msg = segrind_run.send_set_target_cmd(func_desc.location)

                    if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                        raise AssertionError("Could not set target for {}".format(str(func_desc)))
                    resp_msg = segrind_run.read_response()
                    if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                        raise AssertionError("Could not set target for {}".format(str(func_desc)))

                if current_node.is_leaf():
                    try:
                        confirmed, coverage = self._confirm_leaf(func_desc, current_node, segrind_run, max_confirm)
                        if confirmed:
                            # for cov in coverage:
                            #     coverages.append(cov)
                            segrind_run.stop()
                            del segrind_run
                            return current_node, coverages
                        break
                    except RuntimeError as e:
                        # No available hashes, so just mark the identified leaf
                        # as the identified leaf
                        segrind_run.stop()
                        del segrind_run
                        return current_node, coverages
                    except Exception as e:
                        logger.debug("Error confirming leaf for {}: {}".format(func_desc, e))
                        break

                iovec_accepted = False
                try:
                    logger.debug("Trying iovec {} ({})".format(current_node.identifier, current_node.iovec.hexdigest()))
                    iovec_accepted, coverage = self._attempt_ctx(current_node.iovec, segrind_run)
                except Exception as e:
                    logger.debug("Error testing iovec for {}: {}".format(str(func_desc), e))

                if iovec_accepted:
                    current_node = current_node.get_right_child()
                    # coverages.append(coverage)
                else:
                    current_node = current_node.get_left_child()

            segrind_run.stop()
            del segrind_run
            return None, None
        except Exception as e:
            segrind_run.stop()
            del segrind_run
            raise e

    def gen_dtree(self, iovec_coverage_location):
        if not os.path.exists(iovec_coverage_location):
            raise FileNotFoundError(iovec_coverage_location)

        self._log("Loading {}...".format(iovec_coverage_location))
        with open(iovec_coverage_location, "rb") as f:
            iovec_coverages = pickle.load(f)
        self._log("done!")

        labels = preprocessing.LabelEncoder()
        hash_labels = set()
        self._log("Transforming function labels...")
        for fd, coverages in iovec_coverages.items():
            for io_vec, coverage in coverages.items():
                hash_labels.add(io_vec.hexdigest())
        labels.fit_transform(list(hash_labels))
        self._log("done!")

        funcs_labels = list()
        funcs_features = list()
        added_func_descs = dict()
        accepted_iovecs = dict()
        iovec_hash_map = dict()
        coverage_map = dict()

        self._log("Reading in function labels...")
        for fd, coverages in iovec_coverages.items():
            func_desc_hash = hash(fd)
            if func_desc_hash not in added_func_descs:
                self.func_descs.add(fd)
            added_func_descs[func_desc_hash] = fd
            funcs_labels.append(func_desc_hash)
            funcs_features.append(numpy.zeros(len(labels.classes_), dtype=bool))

            for io_vec, coverage in coverages.items():
                hash_sum = io_vec.hexdigest()
                if hash_sum not in coverage_map:
                    coverage_map[hash_sum] = dict()
                coverage_map[hash_sum][fd] = coverage
                iovec_hash_map[hash_sum] = io_vec

                idx = labels.transform([hash_sum])[0]
                self._log("Function {} ({}) accepts IOVec {}".format(func_desc_hash, fd.name, str(io_vec)))
                if func_desc_hash not in accepted_iovecs:
                    accepted_iovecs[func_desc_hash] = set()
                accepted_iovecs[func_desc_hash].add(hash_sum)

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
                self.nodes[index] = FBDecisionTreeInteriorNode(iovec=iovec, coverage=coverage_map[iovec_hash],
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
                            for io_vec, coverage in iovec_coverages[hash_sum].items():
                                confirmation_iovec_hashes.add(io_vec)
                        else:
                            self._log("Func desc {} is not in added_func_descs".format(hash_sum))
                            continue

                current_node.set_equivalence_class(equivalence_class)
                self.equivalence_classes.append(equivalence_class)

                confirmation_iovecs = list()
                for iovec in confirmation_iovec_hashes:
                    if iovec.hexdigest() not in path_iovec_hashes:
                        self._log(
                            "Adding iovec {} to node {}".format(iovec, current_node.identifier))
                        confirmation_iovecs.append(iovec)
                current_node.set_confirmation_iovecs(confirmation_iovecs)
        self._log("done!")

    def __init__(self, iovec_coverage_location):
        self.root = None
        self.func_descs = set()
        self.nodes = dict()
        self.equivalence_classes = list()
        self.gen_dtree(iovec_coverage_location)
