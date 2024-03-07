#include "first.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "base.h"
#include "plugin.h"

#include "sys-time.h"

#include "log.h"
#include "buffer.h"
#include "array.h"
#include "request.h"

#include "sys-unistd.h" /* <unistd.h> */
#include "sys-socket.h"

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#if __GNUC__ && (__clang__ || __GNUC__ >= 5)
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint64_t __attribute__((aligned(8))) __aligned_u64;
#else
/* Define fallback typedefs for non-GCC/Clang compilers */
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long long __aligned_u64 __attribute__((aligned(8)));
#endif

#ifndef MPTCP_INFO
#define MPTCP_INFO 1
#endif
#ifndef SOL_MPTCP
#define SOL_MPTCP 284
#endif
#ifndef MPTCP_FULL_INFO
#define MPTCP_FULL_INFO 4
#endif

#ifdef __linux__
struct mptcp_info {
	__u8	mptcpi_subflows;
	__u8	mptcpi_add_addr_signal;
	__u8	mptcpi_add_addr_accepted;
	__u8	mptcpi_subflows_max;
	__u8	mptcpi_add_addr_signal_max;
	__u8	mptcpi_add_addr_accepted_max;
	__u32	mptcpi_flags;
	__u32	mptcpi_token;
	__u64	mptcpi_write_seq;
	__u64	mptcpi_snd_una;
	__u64	mptcpi_rcv_nxt;
	__u8	mptcpi_local_addr_used;
	__u8	mptcpi_local_addr_max;
	__u8	mptcpi_csum_enabled;
	__u32	mptcpi_retransmits;
	__u64	mptcpi_bytes_retrans;
	__u64	mptcpi_bytes_sent;
	__u64	mptcpi_bytes_received;
	__u64	mptcpi_bytes_acked;
    __u8    mptcpi_subflows_total;
};

struct mptcp_full_info {
	__u32		size_tcpinfo_kernel;	/* must be 0, set by kernel */
	__u32		size_tcpinfo_user;
	__u32		size_sfinfo_kernel;	/* must be 0, set by kernel */
	__u32		size_sfinfo_user;
	__u32		num_subflows;		/* must be 0, set by kernel (real subflow count) */
	__u32		size_arrays_user;	/* max subflows that userspace is interested in;
						 * the buffers at subflow_info/tcp_info
						 * are respectively at least:
						 *  size_arrays * size_sfinfo_user
						 *  size_arrays * size_tcpinfo_user
						 * bytes wide
						 */
	__aligned_u64		subflow_info;
	__aligned_u64		tcp_info;
	struct mptcp_info	mptcp_info;
};
#endif

/* plugin config for all request/connections */

typedef struct {
    fdlog_st *fdlog;
	char use_syslog; /* syslog has global buffer */
	unsigned short syslog_level;
    unsigned char self_disable;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;


#if 0 /* (needed if module keeps state for request) */

typedef struct {
    size_t foo;
} handler_ctx;

__attribute_returns_nonnull__
static handler_ctx * handler_ctx_init(void) {
    return ck_calloc(1, sizeof(handler_ctx));
}

static void handler_ctx_free(handler_ctx *hctx) {
    free(hctx);
}

#endif


/* init the plugin data */
INIT_FUNC(mod_mptcplog_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

/* handle plugin config and check values */

static void mod_mptcplog_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0:{/* mptcplog.filename */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->fdlog = cpv->v.v;
        break;
      }
      case 1: /* accesslog.use-syslog */
        pconf->use_syslog = (int)cpv->v.u;
        break;
      case 2: /* accesslog.syslog-level */
        pconf->syslog_level = cpv->v.shrt;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_mptcplog_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_mptcplog_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_mptcplog_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_mptcplog_merge_config(&p->conf, p->cvlist+p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_mptcplog_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("mptcplog.filename"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mptcplog.use-syslog"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("mptcplog.syslog-level"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_mptcplog"))
        return HANDLER_ERROR;

    config_plugin_value_t *cpv;
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        cpv = p->cvlist + p->cvlist[i].v.u2[0];
        int use_syslog = 0;
        config_plugin_value_t *cpvfile = NULL;
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* accesslog.filename */
                if (!buffer_is_blank(cpv->v.b))
                    cpvfile = cpv;
                else {
                    cpv->v.v = NULL;
                    cpv->vtype = T_CONFIG_LOCAL;
                }
                break;
            }
        }
        if (use_syslog) continue; /* ignore the next checks */
        cpv = cpvfile; /* accesslog.filename handled after preflight_check */
        if (NULL == cpv) continue;
        const char * const fn = cpv->v.b->ptr;
        cpv->v.v = fdlog_open(fn);
        cpv->vtype = T_CONFIG_LOCAL;
        if (NULL == cpv->v.v) {
            log_perror(srv->errh, __FILE__, __LINE__,
              "opening log '%s' failed", fn);
            return HANDLER_ERROR;
        }
    }
    mod_mptcplog_merge_config(&p->defaults, cpv);

    p->conf.self_disable = 0;

    return HANDLER_GO_ON;
}

#ifdef __linux__
void log_mptcp_record(buffer * const b, const request_st * const r, plugin_data *p) {
    struct mptcp_info info;
    socklen_t info_len = sizeof(struct mptcp_info);
    //struct mptcp_full_info fullinfo = {0};
    //socklen_t fullinfo_len = sizeof(struct mptcp_full_info);

    //(-1 == getsockopt(r->con->srv_socket->fd, SOL_MPTCP, MPTCP_FULL_INFO, &fullinfo, &fullinfo_len)) ||
    if (-1 == getsockopt(r->con->fd, SOL_MPTCP, MPTCP_INFO, &info, &info_len)) {
        if (errno == EOPNOTSUPP) {
            log_error(r->conf.errh, __FILE__, __LINE__, "MPTCP disabled or not working, disabling mptcplog");
            p->conf.self_disable = 1;
        }
    }

    unix_time64_t t;
    t = r->start_hp.tv_sec;
	struct tm tm;
    buffer_append_string(b, "{\n\t\"ip_address\": \""); buffer_append_buffer(b, r->dst_addr_buf); buffer_append_char(b, '"');
    //buffer_append_string(b, " ,\n\t\"port_number\": "); buffer_append_buffer(b, r->dst_addr_buf);
    buffer_append_strftime(b, ",\n\t\"timestamp\": \"%Y-%m-%dT%H:%M\"", localtime64_r(&t, &tm));

    buffer_append_string(b, ",\n\t\"mptcp_info\": {");
    if ((int)offsetof(struct mptcp_info, mptcpi_rcv_nxt)-(int)info_len < 0){
        buffer_append_string(b, " \n\t\t\"subflows\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_subflows);
        buffer_append_string(b, ",\n\t\t\"add_addr_signal\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_add_addr_signal);
        buffer_append_string(b, ",\n\t\t\"add_addr_accepted\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_add_addr_accepted);
        buffer_append_string(b, ",\n\t\t\"subflows_max\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_subflows_max);
        buffer_append_string(b, ",\n\t\t\"add_addr_signal_max\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_add_addr_signal_max);
        buffer_append_string(b, ",\n\t\t\"add_addr_accepted_max\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_add_addr_accepted_max);
        buffer_append_string(b, ",\n\t\t\"flags\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_flags);
        buffer_append_string(b, ",\n\t\t\"token\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_token);
        buffer_append_string(b, ",\n\t\t\"write_seq\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_write_seq);
        buffer_append_string(b, ",\n\t\t\"snd_una\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_snd_una);
        buffer_append_string(b, ",\n\t\t\"rcv_nxt\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_rcv_nxt);
    }
    if ((int)offsetof(struct mptcp_info, mptcpi_local_addr_max)-(int)info_len < 0){
        buffer_append_string(b, ",\n\t\t\"local_addr_used\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_local_addr_used);
        buffer_append_string(b, ",\n\t\t\"local_addr_max\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_local_addr_max);
    }
    if ((int)offsetof(struct mptcp_info, mptcpi_csum_enabled)-(int)info_len < 0){
        buffer_append_string(b, ",\n\t\t\"csum_enabled\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_csum_enabled);
    }
    if ((int)offsetof(struct mptcp_info, mptcpi_bytes_acked)-(int)info_len < 0){
        buffer_append_string(b, ",\n\t\t\"retransmits\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_retransmits);
        buffer_append_string(b, ",\n\t\t\"bytes_retrans\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_bytes_retrans);
        buffer_append_string(b, ",\n\t\t\"bytes_sent\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_bytes_sent);
        buffer_append_string(b, ",\n\t\t\"bytes_received\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_bytes_received);
        buffer_append_string(b, ",\n\t\t\"bytes_acked\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_bytes_acked);
    }
    if ((int)offsetof(struct mptcp_info, mptcpi_subflows_total)-(int)info_len < 0){
        buffer_append_string(b, ",\n\t\t\"subflows_total\": "); buffer_append_int(b, (uintmax_t)info.mptcpi_subflows_total);
    }
    buffer_append_string(b, "\n\t}\n}");
}
#endif

SUBREQUEST_FUNC(mod_mptcplog_uri_handler) {
    #ifdef __linux__
    plugin_data * const p = p_d;
    mod_mptcplog_patch_config(r, p);
    fdlog_st * const fdlog = p->conf.fdlog;

    /* No output device, nothing to do */
    if (p->conf.self_disable || (!p->conf.use_syslog && !fdlog)) return HANDLER_GO_ON;

    buffer * const b = (p->conf.use_syslog || fdlog->mode == FDLOG_PIPE)
      ? (buffer_clear(r->tmp_buf), r->tmp_buf)
      : &fdlog->b;

    log_mptcp_record(b, r, p);

    #ifdef HAVE_SYSLOG_H
        if (p->conf.use_syslog) {
            if (!buffer_is_blank(b))
                syslog(p->conf.syslog_level, "%s", b->ptr);
            return HANDLER_GO_ON;
        }
    #endif

    buffer_append_char(b, '\n');

    if (fdlog->mode == FDLOG_PIPE || buffer_clen(b) >= 8192) {
        const ssize_t wr = write_all(fdlog->fd, BUF_PTR_LEN(b));
        buffer_clear(b); /*(clear buffer, even on error)*/
        if (-1 == wr)
            log_perror(r->conf.errh, __FILE__, __LINE__,
              "error flushing log %s", fdlog->fn);
    }
    #endif
    return HANDLER_GO_ON;
}


/* this function is called at dlopen() time and inits the callbacks */
__attribute_cold__
__declspec_dllexport__
int mod_mptcplog_plugin_init(plugin *p);
int mod_mptcplog_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "mptcplog";
	p->init        = mod_mptcplog_init;
	p->set_defaults= mod_mptcplog_set_defaults;

	p->handle_uri_clean = mod_mptcplog_uri_handler;

	return 0;
}