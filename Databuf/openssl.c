#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "openssl.skel.h"
#include "openssl.h"


// 无效的用户ID（UID）和无效的进程ID（PID
#define INVALID_UID -1
#define INVALID_PID -1



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

volatile sig_atomic_t exiting = 0;

const char argp_program_doc[] = "watch openssl data";

// 定义一个结构体，用于存储程序的运行环境和配置选项
struct env {
	pid_t pid;           // 存储要监视的进程ID（PID）
	int uid;             // 存储要监视的用户ID（UID）
	bool extra;          // 布尔值，指示是否显示额外字段（UID, TID）
	char *comm;          // 存储要监视的命令名（进程的命令名）
	bool openssl;       // 布尔值，指示是否显示 OpenSSL 调用
	bool gnutls;        // 布尔值，指示是否显示 GnuTLS 调用
	bool nss;           // 布尔值，指示是否显示 NSS 调用
	bool hexdump;       // 布尔值，指示是否以十六进制格式显示数据
	char *extra_lib;    // 存储额外库的路径
} env = {
	.uid = INVALID_UID, // 初始化 UID 为无效值
	.pid = INVALID_PID, // 初始化 PID 为无效值
	.openssl = true,   // 默认启用 OpenSSL 调用显示
	//.gnutls = true,    // 默认启用 GnuTLS 调用显示
	//.nss = true,       // 默认启用 NSS 调用显示
	.comm = NULL,      // 默认不监视特定的命令（NULL 表示没有指定命令）
};



#define HEXDUMP_KEY 1000
#define EXTRA_LIB_KEY 1003

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Sniff this PID only."},
	{"uid", 'u', "UID", 0, "Sniff this UID only."},
	{"extra", 'x', NULL, 0, "Show extra fields (UID, TID)"},
	{"comm", 'c', "COMMAND", 0, "Sniff only commands matching string."},
	{"no-openssl", 'o', NULL, 0, "Do not show OpenSSL calls."},
	{"no-gnutls", 'g', NULL, 0, "Do not show GnuTLS calls."},
	{"no-nss", 'n', NULL, 0, "Do not show NSS calls."},
	{"hexdump", HEXDUMP_KEY, NULL, 0,
	 "Show data as hexdump instead of trying to decode it as UTF-8"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static bool verbose = false;

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
	switch (key) {
	case 'p':
		env.pid = atoi(arg);
		break;
	case 'u':
		env.uid = atoi(arg);
		break;
	case 'x':
		env.extra = true;
		break;
	case 'c':
		env.comm = strdup(arg);
		break;
	case 'o':
		env.openssl = false;
		break;
	case 'g':
		env.gnutls = false;
		break;
	case 'n':
		env.nss = false;
		break;
	case 'v':
		verbose = true;
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


#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};


// verbose 标志，详细输出
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
						   va_list args) {
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

// 处理在 CPU 上丢失的事件
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void sig_int(int signo) { 
	exiting = 1;
}

int attach_openssl(struct openssl_bpf *skel, const char *lib) {
	// 附加到 SSL_write 
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_write, probe_entry_SSL_write);
	// 附加到 SSL_write 
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_write, probe_ret_SSL_write);
	// 附加到 SSL_read 
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_read, probe_entry_SSL_read);
	// 附加到 SSL_read 
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_read, probe_ret_SSL_read);

	return 0; // 返回成功
}


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


// 将一个字节缓冲区转换为对应的十六进制字符串表示
void buf_to_hex(const uint8_t *buf, size_t len, char *hex_str) {
	for (size_t i = 0; i < len; i++) {
		sprintf(hex_str + 2 * i, "%02x", buf[i]);
	}
}

// 从buf中解析traceid字段
static __always_inline
int extract_trace_id(const char *buf, size_t len, char *trace_id) {
    const char *trace_id_label = "X-Trace:";
    const char *pos = buf;
    const char *end = buf + len;

    while (pos < end) {
        pos = strstr(pos, trace_id_label);
        if (!pos) {
            return 0;  // 未找到 traceid 字段
        }

        // 跳过 "traceid:" 标签
        pos += strlen(trace_id_label);

		// 跳过可能存在的空白字符
        while (pos < end && (*pos == ' ' || *pos == '\t')) {
            pos++;
        }

        // 提取 traceid 值直到下一个空格、回车或换行符
        int i = 0;
        while (pos < end && *pos != ' ' && *pos != '\r' && *pos != '\n' && i < MAX_TRACE_ID_SIZE - 1) {
            trace_id[i++] = *pos++;
        }
        trace_id[i] = '\0';  // 添加 null 终止符
        return 1;  // 找到并提取 traceid 字段
    }

    return 0;  // 未找到 traceid 字段
}


void print_event(struct uprobe_ssl_data_t *event, const char *evt) {
	static unsigned long long start = 0;  // 使用 static 保持函数调用之间的值
	char buf[MAX_BUF_SIZE + 1] = {0};    // 存储事件数据的缓冲区，多一个字节用于 null 终止符
	unsigned int buf_size;

	// 确定缓冲区大小，如果事件数据长度超过缓冲区大小，则使用最大缓冲区大小
	if (event->data_len <= MAX_BUF_SIZE) {
		buf_size = event->data_len;
	} else {
		buf_size = MAX_BUF_SIZE;
	}

	// 根据事件数据的填充情况将数据拷贝到缓冲区
	if (event->buf_filled == 1) {
		memcpy(buf, event->data, buf_size);
	} else {
		buf_size = 0;  // 如果数据未填充，则设置缓冲区大小为 0
	}

	// 如果设置了环境变量 comm，并且事件的 comm 不匹配，则返回
	if (env.comm && strcmp(env.comm, event->comm) != 0) {
		return;
	}

	// 如果这是第一次调用，记录事件的时间戳作为开始时间
	if (start == 0) {
		start = event->timestamp_ns;
	}

	// 计算自事件开始以来的时间（秒）
	double time_s = (double)(event->timestamp_ns - start) / 1000000000;


	// 定义数据标记
	char s_mark[] = "----- DATA -----";
	char e_mark[64] = "----- END DATA -----";
	if (buf_size < event->data_len) {
		snprintf(e_mark, sizeof(e_mark),
				"----- END DATA (TRUNCATED, %d bytes lost) -----",
				event->data_len - buf_size);
	}

	const char* ssl_data_event_type;

	if(event->type == 0){
		ssl_data_event_type = "kSSLRead";
	}
	if(event->type == 1){
		ssl_data_event_type = "kSSLWrite";
	}

// 格式化字符串定义
#define BASE_FMT "%-12s %-18.9f %-16s %-7d %-6d"
#define EXTRA_FMT " %-10d %-10d"

	// 根据环境设置和事件的属性打印事件信息
	if (env.extra) {
		printf(BASE_FMT EXTRA_FMT, ssl_data_event_type, time_s, event->comm, event->pid,
			event->data_len, event->uid, event->tid);
		printf("\n");
	} else {
		printf(BASE_FMT, ssl_data_event_type, time_s, event->comm, event->pid,
			event->data_len);
		printf("\n");	
	}


	// 如果缓冲区不为空，打印数据内容
	if (buf_size != 0) {
		if (env.hexdump) {
			// 为每个字节分配 2 个字符加 null 终止符
			char hex_data[MAX_BUF_SIZE * 2 + 1] = {0};  
			buf_to_hex((uint8_t *)buf, buf_size, hex_data);
			
			// 打印数据的十六进制格式
			printf("\n%s\n", s_mark);
			for (size_t i = 0; i < strlen(hex_data); i += 32) {
				printf("%.32s\n", hex_data + i);
			}
			printf("%s\n\n", e_mark);
		} else {
			// 以文本形式打印数据

			// trace id
			char trace_id[MAX_TRACE_ID_SIZE] = {0};
			extract_trace_id(buf, buf_size, trace_id);
			if (strcmp(trace_id, "") != 0){
				printf("trace ID: %s\n", trace_id);
			}

			printf("\n%s\n%s\n%s\n\n", s_mark, buf, e_mark);
		}
	}
}


static void handle_event(void *ctx, int cpu, void *data, __u32 data_size) {
	struct uprobe_ssl_data_t *e = data;  // 将传入的数据指针转换为 probe_SSL_data_t 结构体指针

	// read/write
	print_event(e, "read/write");
	
}

// argc 是命令行参数数量，argv 是一个指向字符串的指针数组
int main(int argc, char **argv) {
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);  
	struct openssl_bpf *obj = NULL;  
	struct perf_buffer *pb = NULL;   
	int err;

	// argp_parse 将使用 argp 结构体中的配置来解析 argc 和 argv 中的命令行参数
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;  // 如果参数解析失败，返回错误码

	// 设置 libbpf 打印函数
	libbpf_set_print(libbpf_print_fn);

	// 打开 BPF 对象
	obj = openssl_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		goto cleanup;  // 如果打开 BPF 对象失败，跳转到清理代码
	}

	// 在用户态为只读变量 target_uid, target_pid 设置默认值
	// rodata是ebpf的一种机制，用于在加载ebpf程序时传递一些只读数据给ebpf程序
	// 将 env.uid 的值赋给 eBPF 程序的 target_uid 变量。env.uid 是用户指定的目标 UID。
	// 将 env.pid 的值赋给 eBPF 程序的 target_pid 变量。env.pid 是用户指定的目标 PID。如果用户未指定 PID（即 env.pid 等于 INVALID_PID），则将其设置为 0。
	// uid这里默认为 -1 ,pid这里进行了一次判断 env.pid == INVALID_PID 所以 pid 这里默认值为0
	obj->rodata->target_uid = env.uid;     
	obj->rodata->target_pid = env.pid == INVALID_PID ? 0 : env.pid;

	// 加载 BPF 对象
	err = openssl_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;  // 如果加载 BPF 对象失败，跳转到清理代码
	}

	// 如果需要，附加 OpenSSL、GnuTLS 和 NSS 的探针
	if (env.openssl) {
		char *openssl_path = find_library_path("libssl.so");
		printf("OpenSSL path: %s\n", openssl_path);
		attach_openssl(obj, openssl_path);
	}
	

	// 创建性能缓冲区perf_buffer,绑定处理函数handle_event
	pb = perf_buffer__new(bpf_map__fd(obj->maps.tls_perf_array),
							PERF_BUFFER_PAGES, handle_event, handle_lost_events,
							NULL, NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;  // 如果创建性能缓冲区失败，跳转到清理代码
	}

	// 设置 SIGINT 信号处理程序
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;  
	}

	// 打印表头
	printf("%-12s %-18s %-16s %-7s %-7s", "FUNC", "TIME(s)", "COMM", "PID",
			"LEN");
	if (env.extra) {
		printf(" %-10s %-10s", "UID", "TID");
	}

	printf("\n");

	// 进入事件处理循环，循环提取数据
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;  
		}
		err = 0;
	}

cleanup:
	// 释放性能缓冲区和 BPF 对象
	perf_buffer__free(pb);
	openssl_bpf__destroy(obj);
	return err != 0;  
}
