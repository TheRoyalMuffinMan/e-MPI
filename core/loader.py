import re

# Blueprint for entry function
ENTRY = """
// Clocks time of when function entry occurred
int trace_func_entry_NAME(struct pt_regs *ctx) {
    struct event ev = {0};
    // Default arguments
    ev.type = ENTRY;
    ev.pid = bpf_get_current_pid_tgid();
    ev.time = bpf_ktime_get_ns();
    ev.MPI_Request = NULL;
    ev.MPI_Status = NULL;
    ev.ip = PT_REGS_IP(ctx);
    ev.core = bpf_get_smp_processor_id();

    // Copy over function name
    char name[NAME_SIZE] = "DEFAULT_NAME";
    __builtin_memcpy(&ev.name, &name, NAME_SIZE);

    // Handles parsing argument depending on the caller function

    if (events.ringbuf_output(&ev, sizeof(ev), 0) != 0) {
        bpf_trace_printk("Error on submission for process #%d\\n",  ev.pid);
    }

    return 0;
}
"""

# Blueprint for exit function
EXIT = """
// Clocks time of when function returns and determines it's duration
int trace_func_exit_NAME(struct pt_regs *ctx) {
    struct event ev = {0};
    // Default arguments
    ev.type = EXIT;
    ev.pid = bpf_get_current_pid_tgid();
    ev.time = bpf_ktime_get_ns();
    ev.MPI_Request = NULL;
    ev.MPI_Status = NULL;
    ev.ip = PT_REGS_IP(ctx);
    ev.core = bpf_get_smp_processor_id();

    // Copy over function name
    char name[NAME_SIZE] = "DEFAULT_NAME";
    __builtin_memcpy(&ev.name, &name, NAME_SIZE);

    // Handles parsing argument depending on the caller function

    if (events.ringbuf_output(&ev, sizeof(ev), 0) != 0) {
        bpf_trace_printk("Error on submission for process #%d\\n",  ev.pid);
    }

    return 0;
}
"""

# Add argument handling for MPI_Wait
def MPI_Waitall_args(func: str, code: str, entry: str, exit: str) -> str:
    # Replace function name with MPI function
    entry_header = r"(trace_func_entry_)(NAME)"
    exit_header = r"(trace_func_exit_)(NAME)"
    entry = re.sub(entry_header, rf"\1{func}", entry)
    exit = re.sub(exit_header, rf"\1{func}", exit)

    # Replace function name
    entry = re.sub(r"DEFAULT_NAME", func, entry)
    exit = re.sub(r"DEFAULT_NAME", func, exit)

    # Replace PARSE_CALLER_ARGUMENTS label in both entry and exit
    #arguments = """
    #ev.MPI_Request = (void *)PT_REGS_PARM1(ctx);
    #ev.MPI_Status = (void *)PT_REGS_PARM2(ctx);
    #"""
    #entry = re.sub(r"PARSE_CALLER_ARGUMENTS", arguments, entry)
    #exit = re.sub(r"PARSE_CALLER_ARGUMENTS", arguments, exit)

    return code + entry + exit


FUNCTIONS = {
    "MPI_Waitall": MPI_Waitall_args
}


def load_ebpf(path: str) -> str:
    file = open(path, 'r')
    code = file.read()

    # Remove multi-line and single-line comments
    code = re.sub(r'/\*.*?\*/', '', code, flags = re.DOTALL)
    code = re.sub(r'//.*?$', '', code, flags = re.MULTILINE)

    # Handle label replacement
    for func in FUNCTIONS:
        code = FUNCTIONS[func](func, code, ENTRY, EXIT)

    return code
