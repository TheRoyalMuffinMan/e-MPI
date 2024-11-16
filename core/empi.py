#! /usr/bin/python3
# Example Run: sudo python3 empi.py /usr/lib/x86_64-linux-gnu/libmpi.so.40
# in another terminal run: mpirun -np 4 mpi_isend
from bcc import BPF
from loader import *
from event import *
from globals import *
import argparse
import signal
import time
import os
import subprocess
import psutil


# Globals
DEFAULT_DURATION = 75
DEFAULT_EBPF_PATH = "../ebpf/kernel.c"
functions = {} #Dictionary of dictionaries (dictionary per process)
functions_total = {'MPI_Waitall': Function(0, 0, 0)}
last_updated = {} #to match exit with entry of same pid
cores = {}

# Arguments
parser = argparse.ArgumentParser(description="Core program for tracking and reducing voltage for MPI function")
parser.add_argument("-d", "--duration", type = int, help = "total duration of trace, in seconds")
parser.add_argument("path", help = "path to libmpi.so file")

def signal_ignore(signal, frame):
    print()

def bail(error: str) -> None:
    print("Error: " + error)
    exit(1)

def verify_arguments(args) -> None:
    if not args.path or not os.path.isfile(args.path):
        bail("No valid path given")

def process_event(ebpf, ctx, data, size) -> None:
    raw_event = ebpf["events"].event(data)
    event = Event(
       EventType(raw_event.type),
       Arguments(),
       raw_event.name.decode('utf-8'),
       raw_event.pid,
       raw_event.time,
       raw_event.ip,
       raw_event.core
    )
    #print(event)
    # Need to handle determining function (this needs to be done in kernel.c)
    # and need to handle parsing the arguments (let this go to the Argument class in event.py)
    # then reacting to this

    # get dict associated with this pid
    if event.pid not in functions:
        functions[event.pid] = {}


    # get core of this pid
    if event.pid not in cores:
        if event.core > 103:
            cores[event.pid] = event.core - 104
        else:
            cores[event.pid] = event.core

    if event.type == EventType.FUNCTION_ENTRY:
        # get entry in dict
        if event.ip not in functions[event.pid]:
            functions[event.pid][event.ip] = 0 # Function(0, 0, 0)

        # update last_time
        functions[event.pid][event.ip] = event.time # Function(functions[event.pid][event.ip].count, functions[event.pid][event.ip].total, event.time)
        last_updated[event.pid] = event.ip
        #if functions[event.pid][event.ip].count >= 2 and (functions[event.pid][event.ip].total/functions[event.pid][event.ip].count) > 100000:
        if cores[event.pid] == 0 and functions_total['MPI_Waitall'].count >= 2 and (functions_total['MPI_Waitall'].total/functions_total['MPI_Waitall'].count) > 100000:
            # lower frequency
            subprocess.Popen(["cpupower", "frequency-set", "-u", "2000MHz"], stdout=subprocess.DEVNULL)
            #subprocess.Popen(["/usr/local/bin/wrmsr", "0x620", "0x814"])
            #subprocess.Popen(["sudo", "cpupower", "-c", str(cores[event.pid] + 104), "frequency-set", "-u", "1000MHz"], stdout=subprocess.DEVNULL)

    else:
        # update total and count
        total = event.time - functions[event.pid][last_updated[event.pid]] # .last_time
        functions[event.pid][last_updated[event.pid]] = 0 #Function(functions[event.pid][last_updated[event.pid]].count + 1, functions[event.pid][last_updated[event.pid]].total + total, 0)
        functions_total['MPI_Waitall'] = Function(functions_total['MPI_Waitall'].count + 1, functions_total['MPI_Waitall'].total + total, 0)

        #if functions[event.pid][last_updated[event.pid]].count >= 2 and (functions[event.pid][last_updated[event.pid]].total/functions[event.pid][last_updated[event.pid]].count) > 100000:
        if cores[event.pid] == 0 and functions_total['MPI_Waitall'].count >= 2 and (functions_total['MPI_Waitall'].total/functions_total['MPI_Waitall'].count) > 100000:
            # raise frequency
            subprocess.Popen(["cpupower", "frequency-set", "-u", "3800MHz"], stdout=subprocess.DEVNULL)
            #subprocess.Popen(["/usr/local/bin/wrmsr", "0x620", "0x816"])
            #subprocess.Popen(["sudo", "cpupower", "-c", str(cores[event.pid] + 104), "frequency-set", "-u", "3800MHz"], stdout=subprocess.DEVNULL)

def cpu_manufacturer() -> str:
    file = open(CPU_INFO, 'r')
    cpu_info = file.read().lower()

    if "intel" in cpu_info:
        return "intel"
    elif "amd" in cpu_info:
        return "amd"
    else:
        bail("Unsupported CPU manufacturer found")
        return "Unknown"

def determine_configurations() -> None:
    global PHYSICAL_CORES, LOGICAL_CORES, THREADS_PER_CORE, CPU_SOCKETS, MANUFACTURER, CPU_FREQUENCY_RANGE
    PHYSICAL_CORES = psutil.cpu_count(logical = False)
    LOGICAL_CORES = psutil.cpu_count(logical = True)
    THREADS_PER_CORE = PHYSICAL_CORES // LOGICAL_CORES
    CPU_SOCKETS = int(subprocess.check_output('cat /proc/cpuinfo | grep "physical id" | sort -u | wc -l', shell = True))
    MANUFACTURER = cpu_manufacturer()

    if MANUFACTURER == "amd":
        CPU_FREQUENCY_RANGE = list(map(int, open(FREQUENCY_AMD_LOCATION, 'r').read().split()))
    else:
        pass

def main() -> None:
    args = parser.parse_args()
    library = args.path
    duration = args.duration if args.duration else DEFAULT_DURATION
    verify_arguments(args)
    
    determine_configurations()
    print(PHYSICAL_CORES, LOGICAL_CORES, THREADS_PER_CORE, CPU_SOCKETS, MANUFACTURER, CPU_FREQUENCY_RANGE)

    code = load_ebpf(DEFAULT_EBPF_PATH)
    ebpf = BPF(text = code)

    for func in FUNCTIONS:
        ebpf.attach_uprobe(name = library, sym_re = func, fn_name = f"trace_func_entry_{func}")
        ebpf.attach_uretprobe(name = library, sym_re = func, fn_name = f"trace_func_exit_{func}")

    open_uprobes = ebpf.num_open_uprobes()
    if open_uprobes == 0:
        bail(f"0 functions matched by {library}, Exiting....")

    ebpf["events"].open_ring_buffer(lambda ctx, data, size: process_event(ebpf, ctx, data, size))
    start_time = time.time()
    exiting = False
    while not exiting:
        try:
            ebpf.ring_buffer_consume()
            exiting = time.time() - start_time >= duration
        except KeyboardInterrupt:
            exiting = True
            signal.signal(signal.SIGINT, signal_ignore)

    print()
    #for pid in functions:
    #    print(pid)
    #    print(cores[pid])
    #    for ip in functions[pid]:
    #        print(ip)
    #        print(functions[pid][ip])
    #        if (functions[pid][ip].count > 0):
    #            print(f"Average time: {functions[pid][ip].total/functions[pid][ip].count:.2f}")
    #    print()

    print(functions_total)
    if functions_total['MPI_Waitall'].count > 0:
        print(f"Average time: {functions_total['MPI_Waitall'].total/functions_total['MPI_Waitall'].count:.2f}")
    print("Detaching...")

if __name__ == "__main__":
    main()
