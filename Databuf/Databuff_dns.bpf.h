// dns解析

#include "Databuff.bpf.h"

static __always_inline
int _udp_send_skb(struct sk_buff* skb) {
   u16 QR_flags;
    struct sock *sk = BPF_CORE_READ(skb, sk);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);                   
    u16 dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    if ((sport != 53) && (dport != 53)) {
        return 0;     
    }
 
    u32 dns_offset =
        BPF_CORE_READ(skb, transport_header) + sizeof(struct udphdr);
    struct dns_query query;
    // dns头部位置
    bpf_probe_read_kernel(&query.header, sizeof(query.header),
                            BPF_CORE_READ(skb, head) + dns_offset);
   
    QR_flags = __bpf_ntohs(query.header.flags);
    if (QR_flags & 0x8000) {  // 是响应就直接返回
        return 0;
    }

    struct dns_information message = {0};
    bpf_probe_read_kernel(message.data, sizeof(message.data),
                          BPF_CORE_READ(skb, head) + dns_offset +
                              sizeof(struct dns_header));

 
    u16 id = __bpf_ntohs(query.header.id);
    message.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&message.comm, sizeof(message.comm));
    message.id = id;
    message.saddr = saddr;
    message.daddr = daddr;
    message.start_us = bpf_ktime_get_ns();  
    message.qdcount = __bpf_ntohs(query.header.qdcount);
    message.ancount = __bpf_ntohs(query.header.ancount);
    message.nscount = __bpf_ntohs(query.header.nscount);
    message.arcount = __bpf_ntohs(query.header.arcount);

    bpf_map_update_elem(&dns_map, &id, &message, BPF_ANY);
  
    return 0;
}

static __always_inline
int _udp_rcv(struct sk_buff* skb) {
    u16 QR_flags;
    struct sock *sk = BPF_CORE_READ(skb, sk);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    u16 dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if ((sport != 53) && (dport != 53)) {
        return 0;
    }
    u32 dns_offset =
        BPF_CORE_READ(skb, transport_header) + sizeof(struct udphdr);
    struct dns_query query;
    // dns头部位置
    bpf_probe_read_kernel(&query.header, sizeof(query.header),
                          BPF_CORE_READ(skb, head) + dns_offset);
    
    
    QR_flags = __bpf_ntohs(query.header.flags);
    if (!(QR_flags & 0x8000)) {  // 是请求就直接返回
        return 0;
    }
    
    u16 id = __bpf_ntohs(query.header.id);
    struct dns_information* message = bpf_map_lookup_elem(&dns_map, &id);
    if(message == NULL) {
        return 0;
    }
  
    struct dns_information* information;
    information = bpf_ringbuf_reserve(&dns_rb, sizeof(*information), 0);
    if(!information) {
        return 0;
    }
    
    information->pid = message->pid;
    information->id = message->id;
    information->start_us = message->start_us;
    information->end_us = bpf_ktime_get_ns();
    __builtin_memcpy(information->comm, message->comm, sizeof(information->comm));
    __builtin_memcpy(information->data, message->data, sizeof(information->data));
    information->rcode = QR_flags & 0x000F;
    information->saddr = message->saddr;
    information->daddr = message->daddr;
    information->qdcount = message->qdcount;
    information->ancount = message->ancount;
    information->nscount = message->nscount;
    information->arcount = message->arcount;
    
    bpf_ringbuf_submit(information, 0);
    

    return 0;
    

    return 0;
}

