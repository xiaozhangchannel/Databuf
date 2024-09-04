// Databuff内核态入口函数

#include "Databuff_drop.bpf.h"
#include "Databuff_connect.bpf.h"
#include "Databuff_backlog.bpf.h"
#include "Databuff_dns.bpf.h"
#include "Databuff_retrans.bpf.h"
#include "Databuff_socket.bpf.h"
#include "Databuff_hand.bpf.h"

// 丢包检查
SEC("tracepoint/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb* ctx) {
    return _kfree_skb(ctx);
}

// 连接个数
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock* sk) {
    return _tcp_v4_connect_entry(sk);
}

// 失败个数
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    return _tcp_v4_connect_exit(ret);
}

// 连接成功、连接关闭次数
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock* sk) {
    return _tcp_set_state(sk);
}

// 发送 reset 报文次数
SEC("tracepoint/tcp/tcp_send_reset")
int handle_send_reset(struct trace_event_raw_tcp_send_reset* ctx) {
    return _handle_send_reset(ctx);
}


// 全连接、半连接个数
SEC("kprobe/tcp_v4_conn_request")
int BPF_KPROBE(tcp_v4_conn_request, struct sock* sk){
    return __handle_tcp_v4_conn_request(sk);
}

// dns
SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff* skb) {
    return _udp_send_skb(skb);
}

SEC("kprobe/udp_rcv")
int BPF_KPROBE(udp_rcv, struct sk_buff* skb) {
    return _udp_rcv(skb);
}

// retransmit
SEC("kprobe/__tcp_transmit_skb")
int BPF_KPROBE(__tcp_transmit_skb, struct sock* sk) {
    return _tcp_transmit_skb(sk);
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(tcp_retranmit_skb, struct sock* sk) {
    return _tcp_retransmit_skb(sk);
}

SEC("kprobe/tcp_mark_skb_lost")
int BPF_KPROBE(tcp_mark_skb_lost, struct sock* sk) {
    return _tcp_mark_skb_lost(sk);
}

// socket
SEC("kprobe/tcp_sendmsg_locked") 
int BPF_KPROBE(tcp_sendmsg_locked, struct sock* sk) {
    return _tcp_sendmsg_locked(sk);
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock* sk) {
    return _tcp_rcv_established(sk);
}

SEC("kprobe/tcp_try_rmem_schedule")
int BPF_KPROBE(_tcp_try_rmem_schedule, struct sock* sk) {
    return __tcp_try_rmem_schedule(sk);
}

SEC("kprobe/tcp_data_queue")
int BPF_KPROBE(_tcp_data_queue, struct sock* sk) {
    return __tcp_data_queue(sk);
}

SEC("kprobe/tcp_ofo_queue")
int BPF_KPROBE(tcp_ofo_queue, struct sock* sk) {
    return __tcp_ofo_queue(sk);
}

// 握手时延
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
	return handle_tcp_rcv_state_process(ctx, sk);
}

char _license[] SEC("license") = "GPL";
