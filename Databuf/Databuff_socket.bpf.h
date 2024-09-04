// socket 连接相关信息

#include "Databuff.bpf.h"

static __always_inline
int _tcp_sendmsg_locked(struct sock* sk) {
    struct tcp_sock* tp = (struct tcp_sock*)sk;
    // 发送窗口大小
    u32 sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
    // sk->sk_wmem_queued: 套接字的发送队列中当前已排队的内存量
    u32 sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
    // sk->sk_sndbuf: 套接字的发送缓冲区大小
    u32 sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);

    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    struct socketmsg socket = {0};
    socket.daddr = daddr;
    socket.saddr = saddr;
    socket.dport = __bpf_ntohs(dport);
    socket.sport = __bpf_ntohs(sport);
    socket.sndbuf = sndbuf;
    socket.sk_wmem_queued = sk_wmem_queued;
    socket.sk_sndbuf = sk_sndbuf;

    bpf_map_update_elem(&socket_map, &sk, &socket, BPF_ANY);

    return 0;
}


static __always_inline
int _tcp_rcv_established(struct sock* sk) {
    struct tcp_sock* tp = (struct tcp_sock*)sk;

    // 已存在数据包数量
    u32 qlen = BPF_CORE_READ(sk, sk_receive_queue.qlen);
    // 接收方已经确认并准备接收的数据最后一个字节的序列号
    u32 rcv_wup = BPF_CORE_READ(tp, rcv_wup);
    // 期望发送发下次发送的数据字节序列号
    u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);
    // tcp接收窗口大小
    u32 rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);
    // 当前可以接收窗口大小。使用 receive_window < 0 判断零窗口
    u32 receive_window = rcv_wup + rcv_nxt - rcv_wnd;
    // 平滑往返时间 SRTT
    u32 SRTT = BPF_CORE_READ(tp, srtt_us) >> 3;

    struct socketmsg* socket = (struct socketmsg*)bpf_map_lookup_elem(&socket_map, &sk);
    if(!socket) {
        return 0;
    }
    
        socket->qlen = qlen;
        socket->rcv_wup = rcv_wup;
        socket->rcv_nxt = rcv_nxt;
        socket->rcv_wnd = rcv_wnd;
        socket->SRTT = SRTT;
    

    struct socketmsg* socketrb = (struct socketmsg*)bpf_ringbuf_reserve(&socket_rb, sizeof(*socketrb),0);
    if(!socketrb) {
        return 0;
    }

        socketrb->daddr = socket->daddr;
        socketrb->saddr = socket->saddr;
        socketrb->qlen = socket->qlen;
        socketrb->dport = socket->dport;
        socketrb->sport = socket->sport;
        socketrb->sndbuf = socket->sndbuf;
        socketrb->sk_wmem_queued = socket->sk_wmem_queued;
        socketrb->sk_sndbuf = socket->sk_sndbuf;
        socketrb->rcv_wup = socket->rcv_wup;
        socketrb->rcv_nxt = socket->rcv_nxt;
        socketrb->rcv_wnd = socket->rcv_wnd;
        socketrb->receive_window = socket->receive_window;
        socketrb->rmem_alloc = socket->rmem_alloc;
        socketrb->sk_rcvbuf = socket->sk_rcvbuf;
        socketrb->tcp_data = socket->tcp_data;
        socketrb->tcp_ofo = socket->tcp_ofo;
        //socketrb->rcv_ooopack = socket->rcv_ooopack;
        socketrb->SRTT = socket->SRTT;

    bpf_ringbuf_submit(socketrb, 0);
    return 0;
}

static __always_inline
int __tcp_try_rmem_schedule(struct sock* sk) {
    // sk->rmem_alloc 表示当前已分配的接收内存量，内核当前为该 socket 分配的总接收内存量
    u32 rmem_alloc = BPF_CORE_READ(sk, sk_backlog.rmem_alloc.counter);
    
    // sk->sk_rcvbuf 允许的接收缓冲区的最大内存量
    u32 sk_rcvbuf = BPF_CORE_READ(sk, sk_rcvbuf);

    struct socketmsg* socket = (struct socketmsg*)bpf_map_lookup_elem(&socket_map, &sk);
    if(socket) {
        socket->rmem_alloc = rmem_alloc;
        socket->sk_rcvbuf = sk_rcvbuf;
    }
    return 0;
}


static __always_inline
int __tcp_data_queue(struct sock* sk) {
    struct socketmsg* socket = (struct socketmsg*)bpf_map_lookup_elem(&socket_map, &sk);
    if ( socket ) {
        __sync_fetch_and_add(&socket->tcp_data, 1);
    }
    return 0;
}

static __always_inline
int __tcp_ofo_queue(struct sock* sk) {
    struct tcp_sock* tp = (struct tcp_sock*)sk;
    struct socketmsg* socket = (struct socketmsg*)bpf_map_lookup_elem(&socket_map, &sk);
    if( socket ) {
        __sync_fetch_and_add(&socket->tcp_ofo, 1);
    }
    //socket->rcv_ooopack = BPF_CORE_READ(tp, rcv_ooopack);
    return 0;
}