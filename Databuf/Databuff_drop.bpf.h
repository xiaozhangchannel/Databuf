// drop

#include "Databuff.bpf.h"

static __always_inline
int __kfree_skb(struct trace_event_raw_kfree_skb *ctx, struct sk_buff* skb, u16 reason, u64 location) {
    struct sock* sk = BPF_CORE_READ(skb, sk);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    struct dropwatch event = {0};
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    event.daddr = daddr;
    event.saddr = saddr;
    event.sport = __bpf_ntohs(sport);
    event.dport = dport;
    event.family = family;
    event.reason = reason;
    event.location = location;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_perf_event_output(ctx, &drop_perf, BPF_F_CURRENT_CPU, &event, sizeof(struct dropwatch));
    return 0;
}


static __always_inline
int _kfree_skb(struct trace_event_raw_kfree_skb* ctx) {
    struct sk_buff* skb = (struct sk_buff*)ctx->skbaddr;

    u16 reason;
    u64 location;

    if(bpf_core_field_exists(ctx->reason)){
        reason = ctx->reason;
    }

    if(bpf_core_field_exists(ctx->location)){
        location = (long)ctx->location;
    }

    if(bpf_core_field_exists(ctx->reason) && reason <= SKB_DROP_REASON_NOT_SPECIFIED){
        return 0;
    }

    return __kfree_skb(ctx, skb, reason, location);

    return 0;
}
