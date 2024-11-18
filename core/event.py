from enum import Enum
from dataclasses import dataclass
from collections import defaultdict

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
class Record:
    count: int
    total: int
    dvfs_ran: int

class Process():
    def __init__(self, pid, core, functions):
        self.pid = pid
        self.functions = {f: defaultdict(int) for f in functions}
        self.core = core
        self.last_ips = {f: 0 for f in functions}

    def __repr__(self):
        return f"Process(pid={self.pid}, functions={self.functions}, core={self.core}, last_ips={self.last_ips})"

    def set_time(self, function, ip, time):
        self.functions[function][ip] = time
        self.last_ips[function] = ip

    def get_time(self, function, ip):
        return self.functions[function][ip]

    def reset_last_ip(self, function):
        self.last_ips[function] = 0

    def get_last_time(self, function):
        return self.functions[function][self.last_ips[function]]

    def get_core(self):
        return self.core
