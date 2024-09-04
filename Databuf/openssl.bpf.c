#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#include "openssl.h"

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


//创建和初始化 probe_SSL_data_t
static __always_inline 
struct uprobe_ssl_data_t* create_ssl_data_event(u64 current_pid_tgid, u32 current_uid_gid) {
    //键值 0 用于访问 data_buffer_heap 映射中的唯一条目。data_buffer_heap的max_entries为1
    u32 kZero = 0;
    // 
    struct uprobe_ssl_data_t* event = bpf_map_lookup_elem(&data_buffer, &kZero);
    if (event == NULL) {
        return NULL;
    }

    const u32 kMask32b = 0xffffffff;
    event->timestamp_ns = bpf_ktime_get_ns();  // 获取当前时间
    event->pid = current_pid_tgid >> 32;  //进程pid
    event->tid = current_pid_tgid & kMask32b;  //线程tid
    event->uid = current_uid_gid;

    return event;
}


static __always_inline  
int process_SSL_data(struct pt_regs* ctx, u64 pid, u32 uid, enum ssl_event_type type,
                            const char* buf) {
    int ret = 0;
    // 从 pt_regs 结构体中获取返回值，表示读取/写入的字节数
    int len = (int)(ctx)->ax;
    if (len < 0) {
        return 0;
    }

    // 创建一个新的 SSL 数据事件，使用提供的 id (current_pid_tgid)
    // 这里使用指针是可以的，是因为已经分配了内存，如果使用 struct uprobe_ssl_data_t* event; 就是错误的。因为没有分配内存,使用sizeof(uprobe_ssl_data_t)分配内存
    // 最好是使用 BPF_MAP_TYPE_PERCPU_ARRAY 为每个 cpu 都分配一个 map类别
    struct uprobe_ssl_data_t* event = create_ssl_data_event(pid, uid);
    if (event == NULL) {
        return 0;
    }

    //将事件类型设置为传入的 type，ssl_read,ssl_write
    event->type = type;

    // 确定实际数据长度 data_len。如果 len 小于 MAX_DATA_SIZE_OPENSSL，则取 len 和 MAX_DATA_SIZE_OPENSSL - 1 的位与运算结果，否则使用 MAX_DATA_SIZE_OPENSSL 作为数据长度。
    event->data_len = (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1)) : MAX_DATA_SIZE_OPENSSL);
    //使用 bpf_probe_read 从用户空间缓冲区 buf 中读取数据，并存储到事件结构体的 data 字段中
    ret = bpf_probe_read_user(event->data, event->data_len, buf);
    if (!ret)
        event->buf_filled = 1;
    //使用bpf_get_current_comm 获取当前进程的名称
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    //使用 bpf_perf_event_output 将事件数据输出到 tls_events perf buffer。BPF_F_CURRENT_CPU 表示将事件数据发送到当前 CPU 的 perf buffer。
    bpf_perf_event_output(ctx, &tls_perf_array, BPF_F_CURRENT_CPU, event, sizeof(struct uprobe_ssl_data_t));
    return 0;
}


SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs* ctx) {
    //获取当前进程和线程ID
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // 获取当前进程的 UID 和 GID
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    // 如果目标 PID 不为 0 且与当前进程的 PID 不匹配，则返回 0（不处理）
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    // 打印当前进程的 PID
    //bpf_printk("openssl uprobe/SSL_write pid :%d\n", pid);

    // 从 pt_regs 结构体中获取 SSL_write 函数的第二个参数（si），这是 SSL_write 函数中的缓冲区指针 buf
    const char* buf = (const char*)(ctx)->si;
    //将 buf 的地址存储到 active_ssl_write_args_map BPF map 中。
    bpf_map_update_elem(&ssl_write_args_map, &current_pid_tgid, &buf, BPF_ANY);
    return 0;
}

//用于在 SSL_write 函数返回时执行
SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs* ctx) {
    // 获取当前进程的 PID 和 TGID
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    // 获取当前进程的 UID 和 GID
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;


    // 如果目标 PID 不为 0 且不等于当前进程的 PID，则返回
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    // 打印当前进程的 PID
    //bpf_printk("openssl uretprobe/SSL_write pid :%d\n", pid);

    //查找以 current_pid_tgid 作为键的条目。这个 map 存储了 SSL_write 调用时的缓冲区地址
    const char** buf = bpf_map_lookup_elem(&ssl_write_args_map, &current_pid_tgid);
    if (buf != NULL) {
        process_SSL_data(ctx, current_pid_tgid, current_uid_gid, kSSLWrite, *buf);
    }

    //处理完数据后，从 BPF map 中删除当前线程 ID 相关的条目
    bpf_map_delete_elem(&ssl_write_args_map, &current_pid_tgid);
    return 0;
}


SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs* ctx) {
    //获取当前进程和线程ID
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // 获取当前进程的 UID 和 GID
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;


    // 如果目标 PID 不为 0 且与当前进程的 PID 不匹配，则返回 0（不处理）
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    // 打印当前进程的 PID
    //bpf_printk("openssl uprobe/SSL_write pid :%d\n", pid);

    const char* buf = (const char*)(ctx)->si;
    bpf_map_update_elem(&ssl_read_args_map, &current_pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    // 获取当前进程的 PID 和 TGID
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    // 获取当前进程的 UID 和 GID
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;


    // 如果目标 PID 不为 0 且不等于当前进程的 PID，则返回
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    // 打印当前进程的 PID
    //bpf_printk("openssl uretprobe/SSL_write pid :%d\n", pid);

    const char** buf = bpf_map_lookup_elem(&ssl_read_args_map, &current_pid_tgid);
    if (buf != NULL) {
        process_SSL_data(ctx, current_pid_tgid, current_uid_gid, kSSLRead, *buf);
    }

    bpf_map_delete_elem(&ssl_read_args_map, &current_pid_tgid);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
