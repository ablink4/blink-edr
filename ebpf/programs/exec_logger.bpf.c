// NOTE: this file is licensed differently from the rest of the project
// License Identifier: GPL-2.0

#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// data to be sent to the Go program, must match the Go struct exactly
struct event {
    __u32 pid;
    char comm[16];
};

// BPF map definition
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int handle_execve(struct pt_regs *ctx) 
{
    struct event evt = {};

    // get top-level process id (tgid)
    evt.pid = bpf_get_current_pid_tgid() >> 32;

    // get command name of the current task
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return 0; 
}

char LICENSE[] SEC("license") = "GPL";