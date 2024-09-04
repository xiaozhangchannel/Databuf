// 各种连接数

#include "Databuff.bpf.h"

// 发起连接个数
static __always_inline
int _tcp_v4_connect_entry(struct sock* sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct conn_count* count = (struct conn_count*)bpf_map_lookup_elem(&count_map, &pid);
    if(count) {
        __sync_fetch_and_add(&count->total, 1);
    } else {
        struct conn_count initial_count = { .total = 1 };
        initial_count.pid = pid;
        bpf_map_update_elem(&count_map, &pid, &initial_count, BPF_ANY);
    }

    return 0;
}

// 失败次数
static __always_inline
int _tcp_v4_connect_exit(int ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct conn_count* count = (struct conn_count*)bpf_map_lookup_elem(&count_map, &pid);
    if(count) {
        if(ret != 0) {
            __sync_fetch_and_add(&count->failure, 1);
        }
    } else {
        if(ret != 0) {
            struct conn_count initial_count = { .failure = 1 };
            initial_count.pid = pid;
            bpf_map_update_elem(&count_map, &pid, &initial_count, BPF_ANY);
        }
    }
    return 0;
}


// 连接成功、关闭个数
static __always_inline
int _tcp_set_state(struct sock* sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 state = BPF_CORE_READ(sk, __sk_common.skc_state);

    if(state == TCP_ESTABLISHED) {
        struct conn_count* count = (struct conn_count*)bpf_map_lookup_elem(&count_map, &pid);
        if(count) {
            __sync_fetch_and_add(&count->establiehed, 1);
        } else {
            struct conn_count initial_count = { .establiehed = 1 };
            initial_count.pid = pid;
            bpf_map_update_elem(&count_map, &pid, &initial_count, BPF_ANY);
        }

        struct conn_count* data;
        data = (struct conn_count*)bpf_ringbuf_reserve(&count_rb, sizeof(*data), 0);
        if(!data) {
            return 0;
        }
        count = (struct conn_count*)bpf_map_lookup_elem(&count_map, &pid);
        if(count) {
            data->pid = count->pid;
            data->total = count->total;
            data->establiehed = count->establiehed;
            data->failure = count->failure;
            data->fin = count->fin;
            data->reset = count->reset;
        }
        bpf_ringbuf_submit(data, 0);
    }

    if(state == TCP_FIN_WAIT1) {
        struct conn_count* count = (struct conn_count*)bpf_map_lookup_elem(&count_map, &pid);
        if(count) {
            __sync_fetch_and_add(&count->fin, 1);
        } else {
            struct conn_count initial_count = { .fin = 1 };
            initial_count.pid = pid;
            bpf_map_update_elem(&count_map, &pid, &initial_count, BPF_ANY);
        }

    }
    return 0;
}


// reset 次数
static __always_inline
int _handle_send_reset(struct trace_event_raw_tcp_send_reset *ctx) {
    struct sock *sk = (struct sock *)ctx->skaddr;
    if(!sk) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct conn_count* count = (struct conn_count*)bpf_map_lookup_elem(&count_map, &pid);
    if(count) {
        __sync_fetch_and_add(&count->reset, 1);
    } else {
        struct conn_count initial_count = { .reset = 1 };
        initial_count.pid = pid;
        bpf_map_update_elem(&count_map, &pid, &initial_count, BPF_ANY);
    }
    return 0;
}

