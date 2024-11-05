from enum import Enum
from dataclasses import dataclass

class EventType(Enum):
    FUNCTION_ENTRY = 0
    FUNCTION_EXIT = 1

class Arguments:
    def __init__(self) -> None:
        pass

@dataclass
class Event:
    type: EventType
    arguments: Arguments
    name: str
    pid: int
    time: int
    ip: int
    core: int

@dataclass
class Function:
    count: int
    total: int
    last_time: int
