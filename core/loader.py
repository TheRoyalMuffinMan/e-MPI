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
    ev.mpi_count = 0;
    ev.mpi_datatype = 0;
    ev.ip = PT_REGS_IP(ctx);
    ev.core = bpf_get_smp_processor_id();

    // Copy over function name
    char name[NAME_SIZE] = "DEFAULT_NAME";
    __builtin_memcpy(&ev.name, &name, NAME_SIZE);

    // Handles parsing argument depending on the caller function
    PARSE_CALLER_ARGUMENTS

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
    ev.mpi_count = 0;
    ev.mpi_datatype = 0;
    ev.ip = PT_REGS_IP(ctx);
    ev.core = bpf_get_smp_processor_id();

    // Copy over function name
    char name[NAME_SIZE] = "DEFAULT_NAME";
    __builtin_memcpy(&ev.name, &name, NAME_SIZE);

    // Handles parsing argument depending on the caller function
    PARSE_CALLER_ARGUMENTS 

    if (events.ringbuf_output(&ev, sizeof(ev), 0) != 0) {
        bpf_trace_printk("Error on submission for process #%d\\n",  ev.pid);
    }

    return 0;
}
"""

# Generates a entry and exit uprobes for a given MPI_API
def MPI_API_func_generator(func: str, args: str, code: str, entry: str, exit: str) -> str:
    # Replace function name with MPI function
    entry_header = r"(trace_func_entry_)(NAME)"
    exit_header = r"(trace_func_exit_)(NAME)"
    entry = re.sub(entry_header, rf"\1{func}", entry)
    exit = re.sub(exit_header, rf"\1{func}", exit)

    # Replace function name
    entry = re.sub(r"DEFAULT_NAME", func, entry)
    exit = re.sub(r"DEFAULT_NAME", func, exit)

    # Replace PARSE_CALLER_ARGUMENTS label in both entry and exit
    # with custom MPI function arguments
    entry = re.sub(r"PARSE_CALLER_ARGUMENTS", args, entry)
    exit = re.sub(r"PARSE_CALLER_ARGUMENTS", args, exit)

    return code + entry + exit


FUNCTIONS = [
    "MPI_Wait",
    "MPI_Waitall",
    "MPI_Send",
    "MPI_Recv",
    "MPI_Barrier",
    "MPI_Allreduce"
]

FUNCTION_ARGUMENTS = {
    "MPI_Wait": """

    """,
    "MPI_Waitall": """
    ev.mpi_count = (u64)PT_REGS_PARM1(ctx);
    """,
    "MPI_Send": """
    ev.mpi_count = (u64)PT_REGS_PARM2(ctx);
    ev.mpi_datatype = (u64)PT_REGS_PARM3(ctx);
    """,
    "MPI_Recv": """
    ev.mpi_count = (u64)PT_REGS_PARM2(ctx);
    ev.mpi_datatype = (u64)PT_REGS_PARM3(ctx);
    """,
    "MPI_Barrier": """
        
    """,
    "MPI_Allreduce": """
    ev.mpi_count = (u64)PT_REGS_PARM3(ctx);
    ev.mpi_datatype = (u64)PT_REGS_PARM4(ctx);
    """
}


def load_ebpf(path: str) -> str:
    file = open(path, 'r')
    code = file.read()

    # Remove multi-line and single-line comments
    code = re.sub(r'/\*.*?\*/', '', code, flags = re.DOTALL)
    code = re.sub(r'//.*?$', '', code, flags = re.MULTILINE)

    # Handle label replacement
    for func in FUNCTIONS:
        code = MPI_API_func_generator(func, FUNCTION_ARGUMENTS[func], code, ENTRY, EXIT)

    return code
