#include "openssl_trace.bpf.h"

enum ssl_data_event_type { kSSLRead, kSSLWrite };
const u32 invalidFD = 0;

struct ssl_data_event_t {
    enum ssl_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char data[MAX_DATA_SIZE_OPENSSL];
    s32 data_len;
    char comm[TASK_COMM_LEN];
    u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tls_events SEC(".maps");

struct active_ssl_buf {
    u32 fd;
    const char* buf;
};

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ssl_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

// OPENSSL struct to offset , via kern/README.md
typedef long (*unused_fn)();

struct unused {};

struct BIO {
    const struct unused* method;
    unused_fn callback;
    unused_fn callback_ex;
    char* cb_arg; /* first argument for the callback */
    int init;
    int shutdown;
    int flags; /* extra storage */
    int retry_reason;
    int num;
};

struct ssl_st {
    int version;
    struct unused* method;
    struct BIO* rbio;  // used by SSL_read
    struct BIO* wbio;  // used by SSL_write
};

/***********************************************************
 * General helper functions
 ***********************************************************/
static __inline struct ssl_data_event_t* create_ssl_data_event(
    u64 current_pid_tgid) {
    u32 kZero = 0;
    struct ssl_data_event_t* event =
        bpf_map_lookup_elem(&data_buffer_heap, &kZero);
    if (event == NULL) {
        return NULL;
    }

    const u32 kMask32b = 0xffffffff;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;
    event->fd = invalidFD;

    return event;
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/
static int process_SSL_data(struct pt_regs* ctx, u64 id,
                            enum ssl_data_event_type type, const char* buf,
                            u32 fd) {
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }

    struct ssl_data_event_t* event = create_ssl_data_event(id);
    if (event == NULL) {
        return 0;
    }

    event->type = type;
    event->fd = fd;
    // This is a max function, but it is written in such a way to keep older BPF
    // verifiers happy.
    event->data_len =
        (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1))
                                     : MAX_DATA_SIZE_OPENSSL);
    bpf_probe_read(event->data, event->data_len, buf);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event,
                          sizeof(struct ssl_data_event_t));
    return 0;
}

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/

// Function signature being probed:
// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
#endif
    //    debug_bpf_printk("openssl uprobe/SSL_write pid :%d\n", pid);

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
    struct ssl_st ssl_info;
    bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

    struct BIO bio_w;
    bpf_probe_read_user(&bio_w, sizeof(bio_w), ssl_info.wbio);

    // get fd ssl->wbio->num
    u32 fd = bio_w.num;
    //    debug_bpf_printk("openssl uprobe SSL_write FD:%d\n", fd);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.buf = buf;
    bpf_map_update_elem(&active_ssl_write_args_map, &current_pid_tgid,
                        &active_ssl_buf_t, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
#endif
    //    debug_bpf_printk("openssl uretprobe/SSL_write pid :%d\n", pid);
    struct active_ssl_buf* active_ssl_buf_t =
        bpf_map_lookup_elem(&active_ssl_write_args_map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        const char* buf;
        u32 fd = active_ssl_buf_t->fd;
        bpf_probe_read(&buf, sizeof(const char*), &active_ssl_buf_t->buf);
        process_SSL_data(ctx, current_pid_tgid, kSSLWrite, buf, fd);
    }
    bpf_map_delete_elem(&active_ssl_write_args_map, &current_pid_tgid);
    return 0;
}

// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
#endif

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
    struct ssl_st ssl_info;
    bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

    struct BIO bio_r;
    bpf_probe_read_user(&bio_r, sizeof(bio_r), ssl_info.rbio);

    // get fd ssl->rbio->num
    u32 fd = bio_r.num;
    debug_bpf_printk("openssl uprobe PID:%d, SSL_read FD:%d\n", pid, fd);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.buf = buf;
    bpf_map_update_elem(&active_ssl_read_args_map, &current_pid_tgid,
                        &active_ssl_buf_t, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
#endif

    struct active_ssl_buf* active_ssl_buf_t =
        bpf_map_lookup_elem(&active_ssl_read_args_map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        const char* buf;
        u32 fd = active_ssl_buf_t->fd;
        bpf_probe_read(&buf, sizeof(const char*), &active_ssl_buf_t->buf);
        process_SSL_data(ctx, current_pid_tgid, kSSLRead, buf, fd);
    }
    bpf_map_delete_elem(&active_ssl_read_args_map, &current_pid_tgid);
    return 0;
}