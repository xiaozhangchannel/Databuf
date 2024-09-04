#ifndef __OPENSSL_H
#define __OPENSSL_H

// write/read
enum ssl_event_type 
{ 
    kSSLRead = 0, 
    kSSLWrite 
};

#define MAX_ENTRIES 10240    //max_entries最大长度

// const volatile 定义只会在 eBPF 程序的只读数据段（rodata）中创建只读变量。它们的初始值为 0，表示默认情况下不过滤任何特定的进程或用户
const volatile __u64 target_pid = 0;
const volatile __u64 target_uid = 0;

#define MAX_BUF_SIZE 8192 //缓冲区的最大大小
#define TASK_COMM_LEN 16  //定义进程名称或任务名称的最大长度
const __u32 invalidFD = 0;

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
    __u64 timestamp_ns;         // 时间戳，记录事件发生的时间（以纳秒为单位）
    __u32 pid;                  // 进程ID，记录产生该事件的进程ID
    __u32 tid;                  // 线程ID，记录产生该事件的线程ID
    __u32 uid;                  // 用户ID
    int buf_filled;             // 缓冲区是否填充完整
    char data[MAX_DATA_SIZE_OPENSSL]; // 数据缓冲区，用于存储捕获的SSL数据
    __u32 data_len;                    // 数据长度，记录存储在data缓冲区中的数据的长度
    char comm[TASK_COMM_LEN];      // 进程名称，记录产生该事件的进程名称
};


#endif /* __SSLSNIFF_H */   
