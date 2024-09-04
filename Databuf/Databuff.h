// Databuff .h 文件，定义 map 结构
#ifndef __Databuff_H
#define __Databuff_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define MAX_COMM 16

// 协议类型
#define AF_INET 2
#define AF_INET6 10

#define MAX_ENTRIES 10240    //max_entries最大长度

#define PERF_BUFFER_PAGES 16
// 读取数据时间间隔
#define PERF_POLL_TIMEOUT_MS 100

// 每次读取文件长度
#define MAX_LINE_LENGTH 128

// 进程长度
#define TASK_COMM_LEN 16

struct dropwatch {  
    u32 saddr;              // 源ip
    u32 daddr;              // 目的ip
    u16 sport;              // 源端口
    u16 dport;              // 目的端口
    char comm[TASK_COMM_LEN]; // 进程名
    u16 family;             // 协议族
    u16 reason;             // 丢包原因
    long location;           //丢包地址
    u64 pid;                // 进程pid
};

// 连接数
struct conn_count {
    u32 pid;
    u32 total;
    u32 establiehed;
    u32 fin;
    u32 failure; 
    u32 reset;
};

// 半连接、全连接队列长度
struct backlog {
    u32 sk_ack_backlog;
    u32 sk_max_ack_backlog;
};

// dns
struct dns_header {
    u16 id;      // 事务ID
    u16 flags;   // 标志字段
    u16 qdcount; // 问题部分计数
    u16 ancount; // 应答记录计数
    u16 nscount; // 授权记录计数
    u16 arcount; // 附加记录计数
};

struct dns_query {
    struct dns_header header; // DNS头部
    char data[64];            // 可变长度数据（域名+类型+类）
};

struct dns_information {
    u32 pid;
    char comm[MAX_COMM];
    u16 id;
    u32 saddr;
    u32 daddr;
    u32 start_us;
    u32 end_us;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
    char data[64];
    u16 rcode;     //返回标志
};

enum {
    Success = 0,
    server_fault = 2,
    name_fault = 3 
};

// retransmit
struct transmit {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 lost;  // 丢包次数
    u32 count; // 发包次数
    u32 recount; // 重传次数
};

// socket
struct socketmsg {
    u32 saddr;
    u32 daddr;
    u16 dport;
    u16 sport;
    u32 sndbuf; // 发送窗口大小
    u32 sk_wmem_queued; // socket发送缓冲队列当前排队大小
    u32 sk_sndbuf; // 发送缓冲区大小
    u32 qlen; // 当前接收缓冲区中数据包数量
    u32 rcv_wup;
    u32 rcv_nxt;
    u32 rcv_wnd; // 接收窗口大小
    u32 receive_window; // 0窗口数量
    u32 rmem_alloc; // 当前接收缓冲区占用大小
    u32 sk_rcvbuf; // 接收缓冲区总大小
    u32 tcp_data; // 加入接收缓冲区次数
    u32 tcp_ofo; //重排序次数
    u32 SRTT; //平滑往返时间
};

// hand
struct piddata {
	char comm[TASK_COMM_LEN];
	u64 ts;
	u32 tgid;
};

struct event {
    union {
        u32 saddr_v4;
        u8 saddr_v6[16];
    };
    union {
        u32 daddr_v4;
        u8 daddr_v6[16];
    };
    char comm[TASK_COMM_LEN];
    u64 delta_us;
    u64 ts_us;
    u32 tgid;
    int af;
    u16 lport;
    u16 dport;
};


// write/read
enum ssl_event_type 
{ 
    kSSLRead = 0, 
    kSSLWrite 
};

#define MAX_ENTRIES 10240    //max_entries最大长度

// const volatile 定义只会在 eBPF 程序的只读数据段（rodata）中创建只读变量。它们的初始值为 0，表示默认情况下不过滤任何特定的进程或用户
const volatile u64 target_pid = 0;
const volatile u64 target_uid = 0;

#define MAX_BUF_SIZE 8192 //缓冲区的最大大小
#define TASK_COMM_LEN 16  //定义进程名称或任务名称的最大长度
const u32 invalidFD = 0;

#define MAX_TRACE_ID_SIZE 256  //读取trace时单行最大长度

//MAX_DATA_SIZE_OPENSSL：OpenSSL 数据的最大大小，设置为 4KB。
#define MAX_DATA_SIZE_OPENSSL 1024 * 4

// 协议类型
#define AF_INET 2
#define AF_INET6 10
// IP长度
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

struct uprobe_ssl_data_t {
    enum ssl_event_type type; // 事件类型，表示SSL数据事件的类型（例如，读取或写入）
    u64 timestamp_ns;         // 时间戳，记录事件发生的时间（以纳秒为单位）
    u32 pid;                  // 进程ID，记录产生该事件的进程ID
    u32 tid;                  // 线程ID，记录产生该事件的线程ID
    u32 uid;                  // 用户ID
    int buf_filled;             // 缓冲区是否填充完整
    char data[MAX_DATA_SIZE_OPENSSL]; // 数据缓冲区，用于存储捕获的SSL数据
    u32 data_len;                    // 数据长度，记录存储在data缓冲区中的数据的长度
    char comm[TASK_COMM_LEN];      // 进程名称，记录产生该事件的进程名称
};
#endif