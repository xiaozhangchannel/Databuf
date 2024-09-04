// Databuff用户态入口函数

#include "Databuff.h"
#include "dropreason.h"
#include "Databuff.skel.h"
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>


// 无效的用户ID（UID）和无效的进程ID（PID
#define INVALID_UID -1
#define INVALID_PID -1

static char dns_file_path[1024];
static char drop_file_path[1024];
static char count_file_path[1024];
static char hand_file_path[1024];
static char transmit_file_path[1024];
static char socket_file_path[1024];

static volatile bool exiting = false;

struct env {
    bool drop;
    bool count;
    bool backlog;
    bool dns;
    bool transmit;
    bool socket;
    bool hands;
    bool timestamp;
    bool https;
    pid_t pid;           // 存储要监视的进程ID（PID）
	int uid;             // 存储要监视的用户ID（UID）
    bool extra;
    bool hexdump;
} env = {
    .drop = false,
    .count = false,
    .backlog = false,
    .dns = false,
    .transmit = false,
    .socket = false,
    .hands = false,
    .timestamp = false,
    .https = false,
    .pid = INVALID_PID,
    .uid = INVALID_UID,
    .extra = false,
    .hexdump = false
};

#define HEXDUMP_KEY 1000
static const char argp_program_doc[] = "Databuff 0.1\n";
static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Sniff this PID only."},
	{"uid", 'u', "UID", 0, "Sniff this UID only."},
    {"drop", 'D', 0, 0, "Watch drop packet reason"},
    {"count", 'c', 0, 0, "Watch connect packet count"},
    {"backlog", 'b', 0, 0, "Watch backlog packet count"},
    {"dns", 'd', 0, 0, "Watch dns packet message"},
    {"transmit", 't', 0, 0, "Watch transmit packte message"},
    {"socket", 's', 0, 0, "Watch socket packte message"},
    {"hands", 'H', 0, 0, "Watch hands packte message"},
    {"hands", 'T', 0, 0, "Watch hands packte time message"},
    {"https", 'P', 0, 0, "Watch https packte time message"},
    {"extra", 'x', NULL, 0, "Show extra fields (UID, TID)"},
    {"hexdump", HEXDUMP_KEY, NULL, 0,
	 "Show data as hexdump instead of trying to decode it as UTF-8"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {}
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    switch(key) {
        case 'p':
            env.pid = atoi(arg);
            break;
        case 'u':
            env.uid = atoi(arg);
            break;
        case 'D':
            env.drop = true;
            break;
        case 'c':
            env.count = true;
            break;
        case 'b':
            env.backlog = true;
            break;
        case 'd':
            env.dns = true;
            break;
        case 't':
            env.transmit = true;
            break;
        case 's':
            env.socket = true;
            break;        
        case 'H':
            env.hands = true;
            break;  
        case 'T':
            env.timestamp = true;
            break;  
        case 'P':
            env.https = true;
            break; 
        case 'x':
            env.extra = true;
            break;
    	case HEXDUMP_KEY:
		    env.hexdump = true;
		break;
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

enum MonitorMode {
    MODE_DROP_REASON,
    MODE_COUNT_CONN,
    MODE_COUNT_BACKLOG,
    MODE_COUNT_DNS,
    MODE_COUNT_TRANSMIT,
    MODE_COUNT_SOCKET,
    MODE_TIME_HANDS,
    MODE_HTTPS_MSG,
    MODE_DEFAULT
};

enum MonitorMode get_monitor_mode() {
    if(env.drop) {
        return MODE_DROP_REASON;
    } else if (env.count) {
        return MODE_COUNT_CONN;
    } else if (env.backlog) {
        return MODE_COUNT_BACKLOG;
    } else if (env.dns) {
        return MODE_COUNT_DNS;
    } else if (env.transmit) {
        return MODE_COUNT_TRANSMIT;
    } else if (env.socket) {
        return MODE_COUNT_SOCKET;
    } else if (env.hands) {
        return MODE_TIME_HANDS;
    } else if (env.https) {
        return MODE_HTTPS_MSG;
    }
    else {
        env.backlog = true;
        env.drop = true;
        env.count = true;
        env.transmit = true;
        env.socket = true;
        env.hands = true;
        env.timestamp = true;
        env.https = true;
        env.extra = true;
        return MODE_DEFAULT;
    }
}

static void print_header(enum MonitorMode mode) {
    switch (mode) {
        // 丢包
        case MODE_DROP_REASON:
            printf("==============================================================="
                    "CONN_COUNT===================================================="
                    "====\n");
            // 打印字段名
            printf("%-12s %-22s %-22s %-16s %-8s %-8s %-20s %-16s\n",
			        "ts", "saddr:port" ,"daddr:dport", "comm", "pid", "family", "function", "address");    
            break;
        // 连接数
        case MODE_COUNT_CONN:
            printf("==============================================================="
               "CONN_COUNT===================================================="
               "====\n");
            printf("%-10s %-10s %-15s %-10s %-10s %-10s\n" ,
			        "pid", "total" ,"ESTABLISHED", "FIN", "FILURE", "RESET");    
            break;
        // 队列个数
        case MODE_COUNT_BACKLOG:
            printf("==============================================================="
               "CONN_COUNT===================================================="
               "====\n");
            printf("%-10s %-10s\n" ,
			        "pisk_ack_backlogd", "sk_max_ack_backlog" );    
            break;
        case MODE_COUNT_DNS:
            printf("==============================================================="
               "CONN_COUNT===================================================="
               "====\n");
            printf("%-18s %-15s %-5s %-18s %-5s %-5s %-5s %-5s %-45s %-5s %-5s \n",
                        "saddr", "daddr", "pid", "comm", "qd", "an", "ns", "ar", "name", "time", "state");    
            break;
        case MODE_COUNT_TRANSMIT:
            printf("==============================================================="
               "TRANSMIT_COUNT================================================="
               "====\n");
            printf("%-10s %-20s %-22s %-22s %-10s %-10s %-10s\n" ,
			        "pid", "comm", "SADDR:SPORT" ,"DADDR:DPORT", "count", "recount", "lost");    
            break;
        case MODE_COUNT_SOCKET:
            printf("==============================================================="
               "TRANSMIT_COUNT================================================="
               "====\n");
            printf("%-22s %-22s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s\n" ,
			        "SADDR:SPORT" ,"DADDR:DPORT", "sndbuf", "sk_wmem_queued", "sk_sndbuf", "qlen", "rcv_wup", "rcv_nxt", 
                    "rcv_wnd", "receive_window", "rmem_alloc", "sk_rcvbuf", "tcp_data", "tcp_ofo", "SRTT");    
            break;
        case MODE_TIME_HANDS:
            printf("==============================================================="
               "HANDS_COUNT==================================================="
               "====\n");
                if (env.timestamp)
                    printf("%-9s ", ("TIME(s)"));  
                printf("%-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n", "PID", "COMM",
                    "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)");
            break;
        case MODE_HTTPS_MSG:
            // 打印表头
            printf("%-12s %-18s %-16s %-7s %-7s", "FUNC", "TIME(s)", "COMM", "PID",
                    "LEN");
            if (env.extra) {
                printf(" %-10s %-10s", "UID", "TID");
            }
        case MODE_DEFAULT:
        // 如果模式是 MODE_DEFAULT，打印默认信息的表头
            printf("==============================================================="
                "=INFORMATION==================================================="
                "====\n");
            while (!exiting) {
                fprintf(stderr, ".");
                sleep(1);
            }
            break;
    }
}

static void open_log_files() {
    FILE *dns_file = fopen(dns_file_path, "w+");
    if (dns_file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(dns_file);
    FILE *drop_file = fopen(drop_file_path, "w+");
    if (drop_file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(drop_file);
    FILE *count_file = fopen(count_file_path, "w+");
    if (count_file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(count_file);
    FILE *hand_file = fopen(hand_file_path, "w+");
    if (hand_file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(hand_file);
    FILE *transmit_file = fopen(transmit_file_path, "w+");
    if (transmit_file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(transmit_file);
    FILE *socket_file = fopen(socket_file_path, "w+");
    if (socket_file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fclose(socket_file);

}

static void sig_handler(int signo) { exiting = true; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

#define __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe)   \
	do {                                                                       \
	    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name,        \
				   .retprobe = is_retprobe);                                    \
	    skel->links.prog_name = bpf_program__attach_uprobe_opts(                 \
		    skel->progs.prog_name, env.pid, binary_path, 0, &uprobe_opts);       \
	} while (false)


#define __CHECK_PROGRAM(skel, prog_name)               \
	do {                                               \
	  if (!skel->links.prog_name) {                    \
		perror("no program attached for " #prog_name); \
		return -errno;                                 \
	  }                                                \
	} while (false)


#define __ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name,     \
								is_retprobe)                                \
	do {                                                                    \
	  __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe); \
	  __CHECK_PROGRAM(skel, prog_name);                                     \
	} while (false)


#define ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name)     \
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, binary_path, sym_name, prog_name)  \
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, true)



// 函数：查找指定库的路径,通过执行 ldconfig -p | grep libname 
char *find_library_path(const char *libname) {
	// 存储要执行的命令
	char cmd[128];     
	// 用于存储库路径，使用 static 确保函数调用之间的值持久化
	static char path[512]; 
	FILE *fp;          

	
	snprintf(cmd, sizeof(cmd), "ldconfig -p | grep %s", libname);

	// 使用 popen 执行命令并打开管道，读取命令输出
	fp = popen(cmd, "r");
	if (fp == NULL) {
		// 如果命令执行失败，打印错误信息并返回 NULL
		perror("Failed to run ldconfig");
		return NULL;
	}

	// 从命令的输出中读取第一行，应该包含库的路径
	if (fgets(path, sizeof(path) - 1, fp) != NULL) {
		// strrchr查找 '>' 字符的位置，这是 ldconfig 输出格式的一部分
		char *start = strrchr(path, '>');
		if (start && *(start + 1) == ' ') {
			// memmove移动 '>' 之后的字符串到 path 的开始位置
			memmove(path, start + 2, strlen(start + 2) + 1);
			// strchr 查找换行符，并用 '\0' 替换，以终止路径字符串
			char *end = strchr(path, '\n');
			if (end) {
				*end = '\0';  // Null-terminate the path
			}
			// 关闭管道，返回找到的路径
			pclose(fp);
			return path;
		}
	}

	// 关闭管道，如果未找到路径，则返回 NULL
	pclose(fp);
	return NULL;
}

static void set_rodata_flags(struct Databuff_bpf *skel) {
	skel->rodata->target_uid = env.uid;     
	skel->rodata->target_pid = env.pid == INVALID_PID ? 0 : env.pid;
}
static void set_disable_load(struct Databuff_bpf *skel) {
    //dropreason
    bpf_program__set_autoload(skel->progs.kfree_skb,
                                (env.drop) ? true : false);
    // count
    bpf_program__set_autoload(skel->progs.tcp_v4_connect_entry,
                                (env.count) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_v4_connect_exit,
                                (env.count) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_set_state,
                                (env.count) ? true : false);
    bpf_program__set_autoload(skel->progs.handle_send_reset,
                                (env.count) ? true : false);  
    // backlog
    bpf_program__set_autoload(skel->progs.tcp_v4_conn_request,
                                (env.backlog) ? true : false); 
    // dns
    bpf_program__set_autoload(skel->progs.udp_send_skb,
                                (env.dns) ? true : false); 
    bpf_program__set_autoload(skel->progs.udp_rcv,
                                (env.dns) ? true : false); 
    // transmit
    bpf_program__set_autoload(skel->progs.__tcp_transmit_skb, 
                                (env.transmit) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_retranmit_skb, 
                                (env.transmit) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_mark_skb_lost, 
                                (env.transmit) ? true : false);
    // socket
    bpf_program__set_autoload(skel->progs.tcp_sendmsg_locked, 
                                (env.socket) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_rcv_established, 
                                (env.socket) ? true : false);
    bpf_program__set_autoload(skel->progs._tcp_try_rmem_schedule, 
                                (env.socket) ? true : false);
    bpf_program__set_autoload(skel->progs._tcp_data_queue, 
                                (env.socket) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_ofo_queue, 
                                (env.socket) ? true : false);
    // hands 
    bpf_program__set_autoload(skel->progs.tcp_v4_connect, 
                                (env.hands) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_v6_connect, 
                                (env.hands) ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_rcv_state_process, 
                                (env.hands) ? true : false);

}


const char* find_function_by_address(unsigned long address) {
    FILE* file = fopen("/proc/kallsyms", "r");
    if(!file) {
        perror("fopen");
        return NULL;
    }

    static char function_name[256];
    char line[MAX_LINE_LENGTH];
    unsigned long addr;
    char type;
    char symbol[256];

    while(fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%lx %c %s", &addr, &type, symbol) != 3) {
            continue; // 如果解析失败，继续读取下一行
        }

        if (addr == address) {
            // 复制符号名到 function_name 中
            strncpy(function_name, symbol, sizeof(function_name) - 1);
            function_name[sizeof(function_name) - 1] = '\0'; // 确保字符串以 null 结尾
            fclose(file); // 关闭文件
            return function_name; // 返回找到的函数名
        }
    }
    fclose(file);
    return NULL;
}


void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}
void handle_drop(void* ctx, int cpu, void* data, __u32 data_sz) {
    FILE *file = fopen(drop_file_path, "a+"); // 追加
    if (file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
    }

    struct dropwatch *event = data;
    unsigned long address = event->location;
    const char* func_name = find_function_by_address(address);

    // ipv4 IP
    char s_str[INET_ADDRSTRLEN];
	char d_str[INET_ADDRSTRLEN];

    unsigned int saddr = event->saddr;
    unsigned int daddr = event->daddr;

	struct tm *tm;
    time_t t;
    char ts[32];
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);


	const char* family_type;
	if(event->family == 2){
		family_type = "ipv4";
	}

    printf("%-12s %-22s %-22s %-16s %-8lld %-8s %-20s %-16s\n",
            ts,
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)), 
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)), 
			event->comm,
			event->pid,
            family_type,
			func_name,
			SKB_Drop_Reason_Strings[event->reason]
    );
    fprintf(file,
            "%s, %s, %s, %s, %lld, %s, %s, %s \n",
            ts,
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)), 
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)), 
            event->comm, event->pid, family_type, func_name, SKB_Drop_Reason_Strings[event->reason]
            );
    fflush(file);
    fclose(file);

}


// conn_count
static int handle_conn_count(void *ctx, void *event, size_t size) {
    FILE *file = fopen(count_file_path, "a+"); // 追加
    if (file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        return 0;
    }

    const struct conn_count* data = event;
    printf("%-10d %-10d %-15d %-10d %-10d %-10d\n", 
        data->pid,
        data->total,
        data->establiehed,
        data->fin,
        data->failure,
        data->reset
    );
    fprintf(file,
            "%d, %d, %d, %d, %d, %d\n",
                data->pid, data->total, data->establiehed, data->fin, data->failure, data->reset
            );
    fflush(file);
    fclose(file);
    return 0;
}

static int handle_backlog(void *ctx, void *event, size_t size) {
    const struct backlog* data = event;
    printf("%-20d %-20d\n", 
        data->sk_ack_backlog,
        data->sk_max_ack_backlog
    );
    return 0;
}

// 从DNS数据包中提取并打印域名
static void print_domain_name(const unsigned char *data, char *output) {
    const unsigned char *next = data;
    int pos = 0, first = 1;
    // 循环到尾部，标志0
    while (*next != 0) {
        if (!first) {
            output[pos++] = '.'; // 在每个段之前添加点号
        } else {
            first = 0; // 第一个段后清除标志
        }
        int len = *next++; // 下一个段长度

        for (int i = 0; i < len; ++i) {
            output[pos++] = *next++;
        }
    }
    output[pos] = '\0'; // 确保字符串正确结束
}

static int handle_dns(void *ctx, void *event, size_t size) {
    FILE *file = fopen(dns_file_path, "a+"); // 追加
    if (file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        return 0;
    }

    const struct dns_information *pack_info = event;
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];

    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;
    char domain_name[256]; // 用于存储输出的域名

    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));

    print_domain_name((const unsigned char *)pack_info->data, domain_name);
    if (pack_info->daddr == 0) {
        return 0;
    }
    char *state;
    switch(pack_info->rcode) {
        case Success:
            state = "Success";
            break;
        case name_fault:
            state = "name_fault";
        case server_fault:
            state = "server_fault";
            break;
        default:
            break;
    }

    printf("%-18s %-15s %-5d %-18s %-5d %-5d %-5d %-5d %-45s %-5d %-5s \n",
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)), 
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)), 
            pack_info->pid, pack_info->comm,
            pack_info->qdcount, pack_info->ancount, pack_info->nscount, pack_info->arcount,
            domain_name, ((pack_info->end_us) / 1000000)-((pack_info->start_us) / 1000000), state
            );
    fprintf(file,
            "%s, %s, %u, %s, %d, %d, %d, %d, %s, %u, %s\n",
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)), 
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)), 
            pack_info->pid, pack_info->comm,
            pack_info->qdcount, pack_info->ancount, pack_info->nscount, pack_info->arcount,
            domain_name, ((pack_info->end_us) / 1000000)-((pack_info->start_us) / 1000000), state
            );
    fflush(file);
    fclose(file);

        
	return 0;
}

static int handle_transmit(void *ctx, void *event, size_t size) {
    FILE *file = fopen(transmit_file_path, "a+"); // 追加
    if (file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        return 0;
    }
    const struct transmit* data = event;

    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];

    unsigned int saddr = data->saddr;
    unsigned int daddr = data->daddr;


    printf("%-10d %-20s %-22s %-22s %-10d %-10d %-10d\n" ,
        data->pid,
        data->comm,
        inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)), 
        inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)), 
        data->count,
        data->recount,
        data->lost
    );
    fprintf(file,
            "%d, %s, %s, %s, %d, %d, %d \n",
            data->pid, data->comm,
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)), 
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)), 
            data->count, data->recount, data->lost
            );
    fflush(file);
    fclose(file);
    return 0;
}

static int handle_socket(void *ctx, void *event, size_t size) {
    FILE *file = fopen(socket_file_path, "a+"); // 追加
    if (file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
        return 0;
    }
    struct socketmsg* data = event;

    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];

    unsigned int saddr = data->saddr;
    unsigned int daddr = data->daddr;   

    printf("%-22s %-22s %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d\n" ,
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)),
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)),
            (data->sndbuf) / 1024,
            (data->sk_wmem_queued) / 1024,
            (data->sk_sndbuf) / 1024,
            data->qlen,
            (data->rcv_wup) / 1024,
            (data->rcv_nxt) / 1024,
            (data->rcv_wnd) / 1024,
            (data->receive_window) / 1024,
            (data->rmem_alloc) / 1024,
            (data->sk_rcvbuf) / 1024,
            (data->tcp_data) / 1024,
            (data->tcp_ofo) / 1024,
            data->SRTT
            );
    fprintf(file,
            "%s, %s, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n",
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)), 
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)), 
            (data->sndbuf) / 1024,(data->sk_wmem_queued) / 1024,(data->sk_sndbuf) / 1024,
            data->qlen,(data->rcv_wup) / 1024,(data->rcv_nxt) / 1024,
            (data->rcv_wnd) / 1024,(data->receive_window) / 1024,
            (data->rmem_alloc) / 1024,(data->sk_rcvbuf) / 1024,(data->tcp_data) / 1024,
            (data->tcp_ofo) / 1024,data->SRTT
            );
    fflush(file);
    fclose(file);

    return 0;    
}

void handle_hands(void* ctx, int cpu, void* data, __u32 data_sz) {
    FILE *file = fopen(hand_file_path, "a+"); // 追加
    if (file == NULL) {
        fprintf(stderr, "Failed to open udp.log: (%s)\n", strerror(errno));
    }
    const struct event* e = data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    union {
        struct in_addr x4;
        struct in6_addr x6;
    } s, d;
    static __u64 start_ts;

    if (env.timestamp) {
        if (start_ts == 0)
            start_ts = e->ts_us;
        printf("%-9.3f ", (e->ts_us - start_ts) / 1000000.0);
    }
    if (e->af == AF_INET) {
        s.x4.s_addr = e->saddr_v4;
        d.x4.s_addr = e->daddr_v4;
    } else if (e->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "broken event: event->af=%d", e->af);
        return;
    }


    printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", 
                e->tgid, e->comm, e->af == AF_INET ? 4 : 6,
                inet_ntop(e->af, &s, src, sizeof(src)), e->lport,
                inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
                e->delta_us / 1000.0);

    fprintf(file,
            "%d, %s, %d, %s, %d, %s, %d, %f\n",
            e->tgid, e->comm, e->af == AF_INET ? 4 : 6, 
            inet_ntop(e->af, &s, src, sizeof(src)), e->lport,
            inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
            e->delta_us / 1000.0
            );
    fflush(file);
    fclose(file);

}


int main(int argc, char** argv) {
    strcat(dns_file_path, "data/dns.log");
    strcat(drop_file_path, "data/drop.log");
    strcat(count_file_path, "data/count.log");
    strcat(hand_file_path, "data/hand.log");
    strcat(transmit_file_path, "data/transmit.log");
    strcat(socket_file_path, "data/socket.log");
    struct Databuff_bpf* skel;
    struct perf_buffer* drop_pb= NULL;
    struct ring_buffer* count_rb = NULL;
    struct ring_buffer* backlog_rb = NULL;
    struct ring_buffer* dns_rb = NULL;
    struct ring_buffer* transmit_rb = NULL;
    struct ring_buffer* socket_rb = NULL;
    struct perf_buffer* hands_pb= NULL;
    int err;

    if (argc > 1) {
        err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
        if (err)
            return err;
    }

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = Databuff_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }


    set_rodata_flags(skel);
    set_disable_load(skel);

    // 加载和验证 BPF 程序
    err = Databuff_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = Databuff_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 获取监控模式
    enum MonitorMode mode = get_monitor_mode();

    // 打印程序的头部信息
    print_header(mode);

    drop_pb = perf_buffer__new(bpf_map__fd(skel->maps.drop_perf), PERF_BUFFER_PAGES,
                          handle_drop, handle_lost_events, NULL, NULL);
    if (!drop_pb) {
        fprintf(stderr, "failed to open perf buffer(hand_pb): %d\n", errno);
        goto cleanup;
    }
    count_rb = ring_buffer__new(bpf_map__fd(skel->maps.count_rb), handle_conn_count, NULL, NULL);
    if (!count_rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(count_rb)\n");
        goto cleanup;
    }
    backlog_rb = ring_buffer__new(bpf_map__fd(skel->maps.backlog_rb), handle_backlog, NULL, NULL);
    if (!backlog_rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(count_rb)\n");
        goto cleanup;
    }
    dns_rb = ring_buffer__new(bpf_map__fd(skel->maps.dns_rb), handle_dns, NULL, NULL);
    if (!dns_rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(count_rb)\n");
        goto cleanup;
    }
    transmit_rb = ring_buffer__new(bpf_map__fd(skel->maps.transmit_rb), handle_transmit, NULL, NULL);
    if (!transmit_rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(count_rb)\n");
        goto cleanup;
    }
    socket_rb = ring_buffer__new(bpf_map__fd(skel->maps.socket_rb), handle_socket, NULL, NULL);
    if (!socket_rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(count_rb)\n");
        goto cleanup;
    }
    hands_pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
                          handle_hands, handle_lost_events, NULL, NULL);
    if (!drop_pb) {
        fprintf(stderr, "failed to open perf buffer(hand_pb): %d\n", errno);
        goto cleanup;
    }

    open_log_files();
    // 处理事件 
    while (!exiting) {
        // 轮询所有的环形缓冲区
        err = perf_buffer__poll(drop_pb, PERF_POLL_TIMEOUT_MS);
        err = ring_buffer__poll(count_rb, PERF_POLL_TIMEOUT_MS);
        err = ring_buffer__poll(backlog_rb, PERF_POLL_TIMEOUT_MS);
        err = ring_buffer__poll(dns_rb, PERF_POLL_TIMEOUT_MS);
        err = ring_buffer__poll(transmit_rb, PERF_POLL_TIMEOUT_MS);
        err = ring_buffer__poll(socket_rb, PERF_POLL_TIMEOUT_MS);
        err = perf_buffer__poll(hands_pb, PERF_POLL_TIMEOUT_MS);

        sleep(1);
        // Ctrl-C will cause -EINTR 
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }

    }

cleanup:
    perf_buffer__free(drop_pb);
    ring_buffer__free(count_rb);
    ring_buffer__free(backlog_rb);
    ring_buffer__free(dns_rb);
    ring_buffer__free(transmit_rb);
    ring_buffer__free(socket_rb);
    perf_buffer__free(hands_pb);
    return 0;
}