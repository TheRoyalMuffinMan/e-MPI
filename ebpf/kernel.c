#include <uapi/linux/ptrace.h>

#define PAGE_COUNT 1 << 4
#define NAME_SIZE 32

enum event_type {
    ENTRY,
    EXIT
};

struct event {
    // General information
    u8 type;
    u32 pid;
    u64 time;
    u64 ip;
    u64 core;
    char name[NAME_SIZE];

    // Possible arguments
    u64 mpi_count;
    u64 mpi_datatype;
};

// Event ring-buffer, allocations 16 pages of space (4KB * 16 = 64KB total memory allocation)
BPF_RINGBUF_OUTPUT(events, PAGE_COUNT);

/*** Blueprint below (these functions aren't actually called) ****/
// Clocks time of when function entry occurred
int trace_func_entry_NAME(struct pt_regs *ctx) {
    struct event ev;
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
    /* PARSE_CALLER_ARGUMENTS */

    /*if (events.ringbuf_output(&ev, sizeof(ev), 0) != 0) {
        bpf_trace_printk("Error on submission for process #%d\n",  ev.pid);
    }*/

    return 0;
}

// Clocks time of when function returns and determines it's duration
int trace_func_exit_NAME(struct pt_regs *ctx) {
    struct event ev;
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
    /* PARSE_CALLER_ARGUMENTS */

    /*if (events.ringbuf_output(&ev, sizeof(ev), 0) != 0) {
        bpf_trace_printk("Error on submission for process #%d\n",  ev.pid);
    }*/

    return 0;
}
