// 定义map结果，以及一些帮助函数
#ifndef __COMMON_BPF_H
#define __COMMON_BPF_H


#include "Databuff.h"
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>


// drop数据传输
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} drop_perf SEC(".maps");

// 各种连接数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct conn_count);
    __uint(max_entries, MAX_ENTRIES);
} count_map SEC(".maps");

// 连接数 ringbuff
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} count_rb SEC(".maps");

// 全连接、半连接个数
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} backlog_rb SEC(".maps");

// 域名解析
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u16);
    __type(value, struct dns_information);
    __uint(max_entries, MAX_ENTRIES);
} dns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ENTRIES);
} dns_rb SEC(".maps");

// 重传次数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock*);
    __type(value, struct transmit);
    __uint(max_entries, MAX_ENTRIES);
} transmit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ENTRIES);
} transmit_rb SEC(".maps");

// socket
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock*);
    __type(value, struct socketmsg);
    __uint(max_entries, MAX_ENTRIES);
} socket_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ENTRIES);
} socket_rb SEC(".maps");

// 握手
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct piddata);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


// https
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));    //CPU ID
    __uint(value_size, sizeof(u32));   //文件描述符
} tls_perf_array SEC(".maps");

// SSL_read 数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);   //线程 ID             
    __type(value, const char*);   // 传递给 SSL_read 函数的输入数据缓冲区
    __uint(max_entries, MAX_ENTRIES);
} ssl_read_args_map SEC(".maps");


// SSL_write 数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char*);   // 传递给 SSL_write 函数的输出数据缓冲区
    __uint(max_entries, MAX_ENTRIES);
} ssl_write_args_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct uprobe_ssl_data_t);
    __uint(max_entries, 1);
} data_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, MAX_ENTRIES);
} ssl_st_fd SEC(".maps");


struct trace_event_raw_tcp_send_reset {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    const void *skbaddr;
    const void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};


/* help functions */
// 将struct sock类型的指针转化为struct tcp_sock类型的指针
static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk) {
    return (struct tcp_sock *)sk;
}
// 将struct sk_buff类型的指针转化为struct udphdr类型的指针
static __always_inline struct udphdr *skb_to_udphdr(const struct sk_buff *skb) {
    return (struct udphdr *)((
        BPF_CORE_READ(skb, head) +              // 报文头部偏移
        BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}
// 将struct sk_buff类型的指针转化为struct tcphdr类型的指针
static __always_inline struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
    return (struct tcphdr *)((
        BPF_CORE_READ(skb, head) +              // 报文头部偏移
        BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}
// 将struct sk_buff类型的指针转化为struct iphdr类型的指针
static __always_inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(BPF_CORE_READ(skb, head) +
                            BPF_CORE_READ(skb, network_header));
}
// 将struct sk_buff类型的指针转化为struct ipv6hdr类型的指针
static __always_inline struct ipv6hdr *
skb_to_ipv6hdr(const struct sk_buff *skb) {
    return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                              BPF_CORE_READ(skb, network_header));
}


#endif
