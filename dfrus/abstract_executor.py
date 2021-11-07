from abc import ABC
from typing import TypeVar, List, Generic, Callable

X = TypeVar("X")
Y = TypeVar("Y")


class Command(Generic[X, Y]):
    def __init__(self, predicate: Callable[[X], bool], function: Callable[[X], Y]):
        self.predicate = predicate
        self.function = function

    def is_applicable(self, input_object: X) -> bool:
        return self.predicate(input_object)

    def apply(self, input_object: X) -> Y:
        return self.function(input_object)


class Executor(ABC, Generic[X, Y]):
    def __init__(self):
        self._commands: List[Command[X, Y]] = []

    def add_command(self, command: Command[X, Y]):
        self._commands.append(command)

    def execute(self, input_object: X) -> Y:
        for command in self._commands:
            if command.is_applicable(input_object):
                return command.apply(input_object)

        raise ValueError(f"No suitable command for object {input_object!r}")

    def command(self, predicate: Callable[[X], bool]):
        def decorator(function: Callable[[X], Y]):
            self.add_command(Command(predicate, function))
            return function
        return decorator
