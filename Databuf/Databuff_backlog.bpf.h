// 全连接、半连接个数

#include "Databuff.bpf.h"

// 当前连接 半连接、全连接队列长度
static __always_inline
int __handle_tcp_v4_conn_request(struct sock* sk) {
    u32 sk_ack_backlog = BPF_CORE_READ(sk, sk_ack_backlog);
    u32 sk_max_ack_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);

    struct backlog* backlog;
    backlog = (struct backlog*)bpf_ringbuf_reserve(&backlog_rb, sizeof(*backlog), 0);
    if(!backlog){
        return 0;
    }
    backlog->sk_ack_backlog = sk_ack_backlog;
    backlog->sk_max_ack_backlog = sk_max_ack_backlog;
    bpf_ringbuf_submit(backlog, 0);

    bpf_printk("sk_ack_backlog = %d", sk_ack_backlog);
    bpf_printk("sk_maxack_backlog = %d", sk_max_ack_backlog);

    return 0;
}