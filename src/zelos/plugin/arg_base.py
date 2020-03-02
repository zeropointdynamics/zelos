from typing import Any, Callable, Dict, List, Tuple


class Arg:
    def __init__(self, type_str, name, value, string):
        self.type = type_str
        self.name = name
        self.value = value
        self.string = string


class Args:
    def __init__(self, args: List[Arg]) -> None:
        self._args = args
        for a in args:
            setattr(self, a.name, a.value)

    def __str__(self) -> str:
        return ", ".join(self._arg_str_list())

    def _arg_str_list(self) -> List[str]:
        return [a.string for a in self._args]

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """
        Serialize arguments to dictionary list, e.g.:
        args = [ { 'type': 'PCHAR', 'name': 'buf', 'value': 0x12345 } ]
        """
        return [
            {"type": arg.type, "name": arg.name, "value": arg.val}
            for arg in self._args
        ]


class ArgFactory:
    def __init__(self, str_func: Callable[[Arg], str]):
        self._str_func = str_func

    def gen_args(
        self,
        arg_spec: List[Tuple[str, str]],
        values: List[int],
        arg_string_overrides: Dict[str, Callable[[Args], str]] = {},
    ) -> Args:
        arg_list = []

        # We collect the args first since some overrides require all of
        # the arg values. For example, when passed a buffer and a count
        # of bytes to write, we may want to restrict the size of the
        # buffer to print by the count.
        for (type_str, name), val in zip(arg_spec, values):
            arg_list.append(Arg(type_str, name, val, ""))
        args = Args(arg_list)

        for a in args._args:
            if a.name in arg_string_overrides:
                a.string = arg_string_overrides[a.name](args)
            else:
                a.string = self._str_func(a)

        return args
