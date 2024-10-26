#include <uapi/linux/ptrace.h>

// Setup metrics tracking array
BPF_ARRAY(metrics, u64, 2);

// Setup start time tracking hashmap
BPF_HASH(start, u32);

// Clocks time of when function entry occurred
// pt_regs => structure thath olds register state of a CPU at given time
int trace_func_entry(struct pt_regs *ctx) {
    // Returns leftmost (upper) thread group id and rightmost (lower) thread id as 64 bits
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    // Time since system start
    u64 curr_time = bpf_ktime_get_ns();

    // Set the clocked time for the thread ID
    start.update(&pid, &curr_time);

    return 0;
}

// Clocks time of when function returns and determines it's duration
// pt_regs => structure thath olds register state of a CPU at given time
int trace_func_return(struct pt_regs *ctx) {
    // Returns leftmost (upper) thread group id and rightmost (lower) thread id as 64 bits
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    // Get start time
    u64 *start_time = start.lookup(&pid);
    if (start_time == NULL || start_time == 0) {
        return 0;   // Missed start
    }

    // Get the time taken between function enter and exit
    u64 time_taken = bpf_ktime_get_ns() - *start_time;

    // Delete the enter time from the hashmap
    start.delete(&pid);
                
    // Update the latency (time_taken) and increment the count
    u32 lat_idx = 0, cnt_idx = 1;
    metrics.atomic_increment(lat_idx, time_taken);
    metrics.atomic_increment(cnt_idx, 1);

    return 0;
}