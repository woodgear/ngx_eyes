#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "nginx/ngx_connection.h"

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define ADDR_LEN 84

const volatile pid_t target_pid = 0;

static u32 get_tid()
{
	u64 tgid = bpf_get_current_pid_tgid();
	pid_t pid = tgid >> 32;

	if (target_pid != 0 && target_pid != pid)
		return 0;
	return (u32)tgid;
}

#define DATA_LEN 128
SEC("uprobe/ngx_http_init_connection")
int BPF_KPROBE(ngx_http_init_connection_enter, ngx_connection_t *conn)
{
	u32 tid = get_tid();
	if (!tid)
	{
		return 0;
	}

	ngx_connection_t c = {};
	bpf_probe_read_user(&c, sizeof(c), conn);

	char addr[DATA_LEN] = {};
	size_t len = c.addr_text.len & 0xff;
	bpf_probe_read(&addr, len, c.addr_text.data);
	addr[len] = '\0';

	bpf_printk("ngx ngx_http_init_connection PID %d  addr %s \n", tid, addr);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
