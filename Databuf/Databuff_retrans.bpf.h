// 重传次数

#include "Databuff.bpf.h"

static __always_inline
int _tcp_transmit_skb(struct sock* sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32; 
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    struct transmit* transmit_t = (struct transmit*)bpf_map_lookup_elem(&transmit, &sk);
    if(transmit_t) {
        __sync_fetch_and_add(&transmit_t->count, 1);
    } else {
        struct transmit transmit_t = { .count = 1};
        transmit_t.pid = pid;
        bpf_get_current_comm(&transmit_t.comm, sizeof(transmit_t.comm));
        transmit_t.saddr = saddr;
        transmit_t.daddr = daddr;
        transmit_t.dport = __bpf_ntohs(dport);
        transmit_t.lport = __bpf_ntohs(sport);

        bpf_map_update_elem(&transmit, &sk, &transmit_t, BPF_ANY);
    }

    struct transmit* transmits;
    transmits = (struct transmit*)bpf_ringbuf_reserve(&transmit_rb, sizeof(*transmit_t), 0);
    if(!transmits) {
        return 0;
    }
    struct transmit* transmit_tt = (struct transmit*)bpf_map_lookup_elem(&transmit, &sk);
    if (transmit_tt) {
        transmits->pid = transmit_tt->pid;
        transmits->saddr = transmit_tt->saddr;
        transmits->daddr = transmit_tt->daddr;
        __builtin_memcpy(transmits->comm, transmit_tt->comm, sizeof(transmits->comm));
        transmits->lport = transmit_tt->lport;
        transmits->dport = transmit_tt->dport;
        transmits->count = transmit_tt->count;
        transmits->recount = transmit_tt->recount;
        transmits->lost = transmit_tt->lost;
    }
    bpf_ringbuf_submit(transmits, 0);
    return 0;
}

static __always_inline
int _tcp_retransmit_skb(struct sock* sk) {
    struct transmit* transmit_t = (struct transmit*)bpf_map_lookup_elem(&transmit, &sk);
    if(transmit_t) {
        __sync_fetch_and_add(&transmit_t->recount, 1);
    } else {
        struct transmit transmit_tt = { .recount = 1 };
        bpf_map_update_elem(&transmit, &sk, &transmit_tt, BPF_ANY);
    }
    return 0;
}

static __always_inline
int _tcp_mark_skb_lost(struct sock* sk) {
    struct transmit* transmit_t = (struct transmit*)bpf_map_lookup_elem(&transmit, &sk);
    if(transmit_t) {
        __sync_fetch_and_add(&transmit_t->lost, 1);
    } else {
        struct transmit transmit_t = { .lost = 1};
        bpf_map_update_elem(&transmit, &sk, &transmit_t, BPF_ANY);
    }

    return 0;
}

