
#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


// mock
struct ngx_event_s {

};

struct ngx_listening_s {

};
struct ngx_log_s {

};
struct ngx_pool_s {

};

struct ngx_proxy_protocol_s {
};

typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;

typedef int  ngx_socket_t;

typedef struct ngx_event_s ngx_event_t;
typedef struct ngx_listening_s ngx_listening_t;
typedef struct ngx_log_s ngx_log_t;
typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_proxy_protocol_s ngx_proxy_protocol_t;


typedef void*  ngx_recv_pt;
typedef void*  ngx_send_pt;
typedef void*  ngx_recv_chain_pt;
typedef void*  ngx_send_chain_pt;

typedef size_t  socklen_t;


struct ngx_connection_s {
    void               *data;
    ngx_event_t        *read;
    ngx_event_t        *write;

    ngx_socket_t        fd;

    ngx_recv_pt         recv;
    ngx_send_pt         send;
    ngx_recv_chain_pt   recv_chain;
    ngx_send_chain_pt   send_chain;

    ngx_listening_t    *listening;

    off_t               sent;

    ngx_log_t          *log;

    ngx_pool_t         *pool;

    int                 type;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    ngx_str_t           addr_text;
    // ignore those field
};

typedef struct ngx_connection_s ngx_connection_t;
#endif