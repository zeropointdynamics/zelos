from typing import Any, Callable, Dict, Optional

from lark import Lark, Transformer

from zelos.hooks import HookInfo, HookType


"""
ZML or Zelos Manipulation Language is used to specify actions to happen
on more complex conditions.
"""


class ConditionList:
    """
    Specifies common conditions that are used for other ConditionLists
    """

    def __init__(self, conditions: Dict[str, str]):
        self._conditions = conditions
        self._count = 0

    def __str__(self):
        s = str(self._conditions)
        return s

    def is_satisfied(self, zelos):
        thread = self._conditions.get("thread", None)
        if thread is not None and thread != zelos.thread.name:
            return False

        # Count must be the last condition
        self._count += 1
        n = self._conditions.get("n", None)
        if n is not None and n != self._count:
            return False
        else:
            return True


class SyscallConditionList(ConditionList):
    """
    Used to trigger an action after a specific syscall.
    """

    def __init__(self, conditions: Dict[str, str]):
        super().__init__(conditions)

    def is_satisfied(self, zelos, sysname, args, retval):
        if self._conditions["syscall"] != sysname:
            return False

        retval_condition = self._conditions.get("retval", None)
        if retval_condition is not None and retval_condition != retval:
            return False

        arg_conditions = self._conditions.get("arg_", {})
        for (arg_name, expected_arg_val) in arg_conditions.items():
            arg_val = getattr(args, arg_name, None)
            if arg_val is None:
                # This argument is not present for this syscall.
                return False
            if expected_arg_val != arg_val:
                return False

        return super().is_satisfied(zelos)

    def act_when_satisfied(self, zelos, action: Callable[[], Any]):
        def trigger_when(zelos, sysname, args, retval):
            if self.is_satisfied(zelos, sysname, args, retval):
                action()

        hook_info = zelos.hook_syscalls(
            HookType.SYSCALL.AFTER, trigger_when, "on_syscall_conditionlist"
        )
        return hook_info


class FuncConditionList(ConditionList):
    """
    Used to trigger an action after a specific API.
    """

    def __init__(self, conditions: Dict[str, str]):
        super().__init__(conditions)

    def is_satisfied(self, zelos):
        return super().is_satisfied(zelos)

    def act_when_satisfied(self, zelos, action: Callable[[], Any]):
        def trigger_when(zelos):
            if self.is_satisfied(zelos):
                action()

        hook_info = zelos.internal_engine.hook_manager.register_func_hook(
            self._conditions["func"], trigger_when
        )
        return hook_info


class AddressConditionList(ConditionList):
    """
    Used to trigger an action executing a specific address.
    """

    def __init__(self, conditions: Dict[str, str]):
        super().__init__(conditions)

    def act_when_satisfied(self, zelos, action: Callable[[], Any]):
        def trigger_when(zelos, address, size):
            if self.is_satisfied(zelos):
                action()

        address = self._conditions["addr"]

        hook_info = zelos.hook_execution(
            HookType.EXEC.INST,
            trigger_when,
            ip_low=address,
            ip_high=address,
            name="on_thread_conditionlist",
        )
        return hook_info


class ThreadConditionList(ConditionList):
    """
    Used to trigger an action upon switching to a certain thread.
    """

    def __init__(self, conditions: Dict[str, str]):
        super().__init__(conditions)

    def act_when_satisfied(self, zelos, action: Callable[[], Any]):
        def trigger_when(old_thread):
            if self.is_satisfied(zelos):
                action()

        hook_info = zelos.internal_engine.hook_manager.register_thread_hook(
            HookType.THREAD.SWAP, trigger_when, "on_thread_conditionlist"
        )
        return hook_info


class EmptyConditionList:
    """
    When no condition to activate an action is specified, default to
    enacting the action right now.
    """

    def act_when_satisfied(self, zelos, action: Callable[[], Any]):
        # Nothing stopping this from immediately happening.
        action()
        return None


class ZmlParser:
    """
    A parser for the ZML language. Can be used to generate condition
    lists.
    """

    def __init__(self, zelos):
        self.zelos = zelos

        self._zml_parser = Lark(
            r"""condition_list : """
            + r"""[condition [WS] ("," [WS] condition [WS])* "," [WS]] """
            + r"""event_condition [WS] ("," [WS] condition [WS])* """
            + r"""
            condition : thread_cond|n_cond|retval_cond|arg_cond

            event_condition : func_event|syscall_event|thread_event|addr_event
            func_event : "func" equals CNAME
            syscall_event : "syscall" equals CNAME
            thread_event : "thread" equals CNAME
            addr_event : "addr" equals NUMBER

            thread_cond : "thread" equals CNAME
            n_cond : "n" equals NUMBER
            retval_cond : "retval" equals NUMBER
            arg_cond : "arg_" CNAME equals NUMBER

            equals : [WS] "=" [WS]

            NUMBER : HEXNUMBER|SIGNED_NUMBER
            HEXNUMBER.2: ["-"] "0x" HEXDIGIT+
            NAME : CNAME

            %import common.HEXDIGIT
            %import common.SIGNED_NUMBER
            %import common.CNAME
            %import common.WS

            """,
            start="condition_list",
        )

    def trigger_on_zml(self, action: Callable[[], Any], zml_string: str):
        zml_object = self.parse_zml_string(zml_string)
        if zml_object is None:
            return
        zml_object.act_when_satisfied(self.zelos, action)

    def parse_zml_string(self, zml_string: str) -> Optional[HookInfo]:
        if zml_string == "":
            return EmptyConditionList()

        tree = self._zml_parser.parse(zml_string)
        return ZmlTransformer(visit_tokens=True).transform(tree)


class ZmlTransformer(Transformer):
    """
    Takes a ZML tree and creates a ConditionList object out of it.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._condition_list_type = None
        self._conditions = {}
        self._args = {}

    def condition_list(self, tree):
        if len(self._args) > 0:
            self._conditions["arg_"] = self._args
        return self._condition_list_type(self._conditions)

    def thread_event(self, children):
        self._condition_list_type = ThreadConditionList
        self._conditions["thread"] = children[1]

    def func_event(self, children):
        self._condition_list_type = FuncConditionList
        self._conditions["func"] = children[1]

    def syscall_event(self, children):
        self._condition_list_type = SyscallConditionList
        self._conditions["syscall"] = children[1]

    def addr_event(self, children):
        self._condition_list_type = AddressConditionList
        self._conditions["addr"] = children[1]

    def thread_cond(self, children):
        self._conditions["thread"] = children[1]

    def n_cond(self, children):
        self._conditions["n"] = children[1]

    def retval_cond(self, children):
        self._conditions["retval"] = children[1]

    def arg_cond(self, children):
        self._args[children[0]] = children[2]

    def NUMBER(self, s):
        return int(s.value, 0)

    def CNAME(self, s):
        return s.value
