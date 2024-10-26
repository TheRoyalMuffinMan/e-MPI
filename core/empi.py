#! /usr/bin/python3
# Example Run: sudo python3 empi.py /usr/lib/x86_64-linux-gnu/libmpi.so.40
# in another terminal run: mpirun -np 4 mpi_hello_world
from bcc import BPF
from time import sleep
import argparse
import signal
import os
import re

# Globals
FUNCTIONS = [
    "MPI_Wait",
    "MPI_Get_processor_name",
    "MPI_Comm_rank"
]
DEFAULT_DURATION = 60
DEFAULT_EBPF_PATH = "../ebpf/kernel.c"

# Arguments
parser = argparse.ArgumentParser(description="Core program for tracking and reducing voltage for MPI function")
parser.add_argument("-d", "--duration", type = int, help = "total duration of trace, in seconds")
parser.add_argument("path", help = "path to libmpi.so file")

# signal handler
def signal_ignore(signal, frame):
    print()

def bail(error: str) -> None:
    print("Error: " + error)
    exit(1)

def load_ebpf(path: str) -> str:
    file = open(path, 'r')
    code = file.read()
    # Remove multi-line and single-line comments
    code = re.sub(r'/\*.*?\*/', '', code, flags = re.DOTALL)
    code = re.sub(r'//.*?$', '', code, flags = re.MULTILINE)
    return code

def verify_arguments(args) -> None:
    if not args.path or not os.path.isfile(args.path):
        bail("No valid path given")

def main() -> None:
    args = parser.parse_args()
    verify_arguments(args)
    library = args.path
    duration = args.duration if args.duration else DEFAULT_DURATION
    code = load_ebpf(DEFAULT_EBPF_PATH)
    ebpf = BPF(text = code)

    for func in FUNCTIONS:
        ebpf.attach_uprobe(name = library, sym_re = func, fn_name = "trace_func_entry")
        ebpf.attach_uretprobe(name = library, sym_re = func, fn_name = "trace_func_return")

    open_uprobes = ebpf.num_open_uprobes()
    if open_uprobes == 0:
        bail(f"0 functions matched by {library}, Exiting....")

    exiting = False
    seconds = 0
    while not exiting:
        try:
            sleep(duration)
            seconds += duration
        except KeyboardInterrupt:
            exiting = True
            # as cleanup can take many seconds, trap Ctrl-C:
            signal.signal(signal.SIGINT, signal_ignore)
        if args.duration and seconds >= args.duration:
            exiting = True

        total  = ebpf['metrics'][0].value
        counts = ebpf['metrics'][1].value
        if counts > 0:
            print("\navg = %ld %s, total: %ld %s, count: %ld\n" %(total/counts, "nsecs", total, "nsecs", counts))
        ebpf['metrics'].clear()

    print("Detaching...")

if __name__ == "__main__":
    main()