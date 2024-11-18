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

# Global structures
processes = {} # Dictionary of Process classes
total_tracker = {} # Summation across all processes
core_zero_pid = 0

# Arguments
parser = argparse.ArgumentParser(description="Core program for tracking and reducing voltage for MPI function")
parser.add_argument("-d", "--duration", type = int, help = "total duration of trace, in seconds")
parser.add_argument("path", help = "path to libmpi.so file")

def signal_ignore(signal, frame):
    print()

def bail(error: str) -> None:
    print("Error: " + error)
    exit(1)

def process_event(ebpf, ctx, data, size) -> None:
    raw_event = ebpf["events"].event(data)
    event = Event(
       EventType(raw_event.type),
       Arguments(raw_event.mpi_count, raw_event.mpi_datatype),
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

    # init Process for this pid
    if event.pid not in processes:
        core = event.core
        if event.core > PHYSICAL_CORES - 1:
            core = event.core - PHYSICAL_CORES
        processes[event.pid] = Process(event.pid, core, FUNCTIONS)
        global core_zero_pid

        if core == 0:
            core_zero_pid = event.pid

    global FREQ_LOWERED

    if event.type == EventType.FUNCTION_ENTRY:
        # update last_time
        processes[event.pid].set_time(event.name, event.ip, event.time)

        if processes[event.pid].get_core() == 0 and total_tracker[event.name].count >= 2 and (total_tracker[event.name].total/total_tracker[event.name].count) > 100000 and FREQ_LOWERED == 0: # allow only one core to be in charge for per-socket DVFS
            # lower frequency
            subprocess.Popen(["cpupower", "frequency-set", "-u", "2000MHz"], stdout=subprocess.DEVNULL)
            total_tracker[event.name].dvfs_ran += 1
            FREQ_LOWERED = 1
            #print("Lowering for " + event.name)
            #subprocess.Popen(["/usr/local/bin/wrmsr", "0x620", "0x814"])
            #subprocess.Popen(["sudo", "cpupower", "-c", str(cores[event.pid] + 104), "frequency-set", "-u", "1000MHz"], stdout=subprocess.DEVNULL)

    else:
        # update total and count
        total = event.time - processes[event.pid].get_last_time(event.name)
        if total != event.time:
            processes[event.pid].reset_last_ip(event.name)
        else:
            total = 0 # Bookkeeping error...
        total_tracker[event.name] = Record(total_tracker[event.name].count + 1, total_tracker[event.name].total + total, total_tracker[event.name].dvfs_ran)

        if processes[event.pid].get_core() == 0 and FREQ_LOWERED == 1:
            # raise frequency
            subprocess.Popen(["cpupower", "frequency-set", "-u", str(CPU_FREQUENCY_RANGE[0])], stdout=subprocess.DEVNULL)
            FREQ_LOWERED = 0
            #print("Increasing for " + event.name)
            #subprocess.Popen(["/usr/local/bin/wrmsr", "0x620", "0x816"])
            #subprocess.Popen(["sudo", "cpupower", "-c", str(cores[event.pid] + 104), "frequency-set", "-u", "3800MHz"], stdout=subprocess.DEVNULL)

# Determines CPU manufacturer from cpuinfo system info
def cpu_manufacturer() -> str:
    file = open(CPU_INFO, 'r')
    cpu_info = file.read().lower()
    file.close()

    if "intel" in cpu_info:
        return "intel"
    elif "amd" in cpu_info:
        return "amd"
    else:
        bail("Unsupported CPU manufacturer found")
        return "Unknown"

# Determines initial architecture configurations for frequency scaling
def determine_configurations() -> None:
    global PHYSICAL_CORES, LOGICAL_CORES, THREADS_PER_CORE, CPU_SOCKETS, MANUFACTURER, CPU_FREQUENCY_RANGE, FREQ_LOWERED
    PHYSICAL_CORES = psutil.cpu_count(logical = False)
    LOGICAL_CORES = psutil.cpu_count(logical = True)
    THREADS_PER_CORE = LOGICAL_CORES // PHYSICAL_CORES
    CPU_SOCKETS = int(subprocess.check_output('cat /proc/cpuinfo | grep "physical id" | sort -u | wc -l', shell = True))
    MANUFACTURER = cpu_manufacturer()

    FREQ_LOWERED = 0

    if MANUFACTURER == "amd":
        CPU_FREQUENCY_RANGE = list(map(int, open(FREQUENCY_AMD_LOCATION, 'r').read().split()))
    else:
        CPU_FREQUENCY_RANGE = list(map(int, [open(FREQUENCY_MAX_INTEL_LOCATION, 'r').read(), open(FREQUENCY_MIN_INTEL_LOCATION, 'r').read()]))

# Checks if arguments meet compliance
def verify_arguments(args) -> None:
    if not args.path or not os.path.isfile(args.path):
        bail("No valid path given")

    if args.duration != None and (not isinstance(args.duration, int) or args.duration < 10):
        bail("Didn't pass in integer for duration or duration is too short (must be greater than 10 seconds)")

def main() -> None:
    # Parse arguments and verify them
    args = parser.parse_args()
    library = args.path
    duration = args.duration if args.duration else DEFAULT_DURATION
    verify_arguments(args)

    # Determine initial CPU information
    determine_configurations()

    # Set to max frequency
    subprocess.Popen(["cpupower", "frequency-set", "-u", str(CPU_FREQUENCY_RANGE[0])], stdout=subprocess.DEVNULL)

    # Generate the ebpf code and load it
    code = load_ebpf(DEFAULT_EBPF_PATH)
    ebpf = BPF(text = code)

    # Attach all MPI Supported functions (MPI_Wait, MPI_Waitall, etc....)
    for func in FUNCTIONS:
        ebpf.attach_uprobe(name = library, sym = func, fn_name = f"trace_func_entry_{func}")
        ebpf.attach_uretprobe(name = library, sym = func, fn_name = f"trace_func_exit_{func}")
        total_tracker[func] = Record(0, 0, 0)

    # Check if we have opened more than one uprobe
    open_uprobes = ebpf.num_open_uprobes()
    if open_uprobes == 0:
        bail(f"0 functions matched by {library}, Exiting....")

    # Start processing events from the ring buffer
    ebpf["events"].open_ring_buffer(lambda ctx, data, size: process_event(ebpf, ctx, data, size))
    start_time = time.time()
    exiting = False
    global core_zero_pid
    while not exiting:
        try:
            ebpf.ring_buffer_consume()
            exiting = time.time() - start_time >= duration
        except KeyboardInterrupt:
            exiting = True
            signal.signal(signal.SIGINT, signal_ignore)

        if core_zero_pid != 0:
            print("Reattching probes to pid " + str(core_zero_pid))
            for func in FUNCTIONS:
                ebpf.detach_uprobe(name = library, sym = func)
                ebpf.detach_uretprobe(name = library, sym = func)

                ebpf.attach_uprobe(name = library, sym = func, fn_name = f"trace_func_entry_{func}", pid = core_zero_pid)
                ebpf.attach_uretprobe(name = library, sym = func, fn_name = f"trace_func_exit_{func}", pid = core_zero_pid)
            core_zero_pid = 0

    print("Detaching...")

    # Write all tracked information to a log file
    file = open(DEFAULT_OUTPUT_FILE, 'w')
    ###################### Write statistic information here
    file.close()

    # Set to max frequency
    subprocess.Popen(["cpupower", "frequency-set", "-u", str(CPU_FREQUENCY_RANGE[0])], stdout=subprocess.DEVNULL)

    #for pid in processes:
    #    print(processes[pid])

    for func in FUNCTIONS:
        if total_tracker[func].count > 0:
            print(f"{func}: {total_tracker[func]}, avg {total_tracker[func].total/total_tracker[func].count/1000} us")

if __name__ == "__main__":
    main()
