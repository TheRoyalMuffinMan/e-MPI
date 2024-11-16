from enum import Enum
from dataclasses import dataclass

class EventType(Enum):
    FUNCTION_ENTRY = 0
    FUNCTION_EXIT = 1

@dataclass
class Arguments:
    count: int
    datatype: int

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
