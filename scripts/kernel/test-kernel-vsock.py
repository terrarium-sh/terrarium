#!/usr/bin/env python3
"""Compile shipped socket wrapper and transport credit paths without a VM."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'kernel/patches/0004-terra-socket-vsock.patch'


def read_overlay_source(name: str) -> str:
    return (ROOT / 'kernel/overlay' / name).read_text()


def declaration(source: str, expression: str) -> str:
    match = re.search(expression, source, re.MULTILINE)
    if match is None:
        raise ValueError(expression)
    begin = source.index('{', match.start())
    depth = 1
    end = begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def patched_source(name: str) -> str:
    selected = False
    lines = []
    for line in PATCH.read_text().splitlines():
        if line.startswith('+++ '):
            selected = line == f'+++ b/{name}'
        elif selected and line.startswith((' ', '+')):
            lines.append(line[1:])
    if not lines:
        raise ValueError(f'missing {name} in patch')
    return '\n'.join(lines)


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef unsigned int __poll_t;
typedef struct poll_table poll_table;
struct poll_table {int marker;};
struct file;
typedef uint16_t __be16;
typedef uint32_t __be32;
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(type,a,b) min((type)(a),(type)(b))
#define max_t(type,a,b) ((type)(a)>(type)(b)?(type)(a):(type)(b))
#define DIV_ROUND_UP(value,divisor) (((value)+(divisor)-1)/(divisor))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(target,value) ((target)=(value))
#define xchg(target,value) ({__typeof__(*(target)) old=*(target);*(target)=(value);old;})
#define SHUT_RDWR 2
#define SEND_SHUTDOWN 2
#define RCV_SHUTDOWN 1
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define TCP_CLOSING 11
#define SS_CONNECTED 3
#define SHUTDOWN_MASK 3
#define MSG_DONTWAIT 1
#define MSG_PEEK 2
#define MSG_NOSIGNAL 4
#define MSG_ERRQUEUE 8
#define SOL_SOCKET 1
#define SOL_IP 2
#define SOL_IPV6 3
#define SOL_UDP 17
#define SO_RCVBUF 1
#define SO_SNDBUF 2
#define IP_RECVERR 3
#define IP_TTL 4
#define IPV6_RECVERR 5
#define IP_TOS 6
#define IPV6_TCLASS 7
#define IP_PKTINFO 8
#define IPV6_PKTINFO 9
#define UDP_SEGMENT 103
#define GFP_KERNEL 0
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define TERRA_SOCKET_EXTERNAL 2
#define TERRA_SOCKET_NATIVE 1
#define VIRTIO_VSOCK_OP_CREDIT_REQUEST 7
#define EXPORT_SYMBOL_GPL(name)
#define smp_load_acquire(value) (*(value))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
static u16 htons(u16 value) {return __builtin_bswap16(value);}
static u16 ntohs(u16 value) {return __builtin_bswap16(value);}
static u32 htonl(u32 value) {return __builtin_bswap32(value);}
static u16 get_unaligned_le16(const void *p) {const u8 *b=p;return b[0]|b[1]<<8;}
static u32 get_unaligned_le32(const void *p) {const u8 *b=p;return b[0]|b[1]<<8|b[2]<<16|(u32)b[3]<<24;}
static void put_unaligned_le16(u16 v,void *p) {u8 *b=p;b[0]=v;b[1]=v>>8;}
static void put_unaligned_le32(u32 v,void *p) {u8 *b=p;b[0]=v;b[1]=v>>8;b[2]=v>>16;b[3]=v>>24;}
struct in_addr {__be32 s_addr;};
struct in6_addr {union {u8 s6_addr[16];__be32 s6_addr32[4];};};
struct sockaddr_storage {u16 ss_family;u8 padding[126];};
struct sockaddr {u16 sa_family;};
struct sockaddr_in {u16 sin_family;__be16 sin_port;struct in_addr sin_addr;u8 padding[8];};
struct sockaddr_in6 {u16 sin6_family;__be16 sin6_port;u32 sin6_flowinfo;struct in6_addr sin6_addr;u32 sin6_scope_id;};
static bool ipv6_addr_v4mapped(const struct in6_addr *a) {
 return !a->s6_addr32[0]&&!a->s6_addr32[1]&&a->s6_addr32[2]==htonl(0xffff);
}
static bool ipv6_addr_equal(const struct in6_addr *a,const struct in6_addr *b) {return !memcmp(a,b,16);}
static bool ipv6_addr_any(const struct in6_addr *a) {return !(a->s6_addr32[0]|a->s6_addr32[1]|a->s6_addr32[2]|a->s6_addr32[3]);}
struct in_pktinfo {int ipi_ifindex;struct in_addr ipi_spec_dst,ipi_addr;};
struct in6_pktinfo {struct in6_addr ipi6_addr;unsigned int ipi6_ifindex;};
struct work_struct {int queued;};
struct delayed_work {struct work_struct work;};
struct mutex {int locked;};
static void mutex_lock(struct mutex *m) {assert(!m->locked);m->locked=1;}
static void mutex_unlock(struct mutex *m) {assert(m->locked);m->locked=0;}
static int select_lock_error;
static void (*select_lock_hook)(void);
static int mutex_lock_interruptible(struct mutex *m) {
 if(select_lock_error)return select_lock_error;
 if(select_lock_hook) {select_lock_hook();select_lock_hook=NULL;}
 mutex_lock(m);return 0;
}
#define to_delayed_work(work) container_of(work,struct delayed_work,work)
#define time_before(first,second) ((long)((second)-(first))>0)
static unsigned long jiffies,timeout_delay;
static void *system_unbound_wq;
static void mod_delayed_work(void *queue,struct delayed_work *work,unsigned long delay) {
 (void)queue;work->work.queued++;timeout_delay=delay;
}
static void cancel_delayed_work(struct delayed_work *work) {work->work.queued=0;}
static void queue_work(void *queue,struct work_struct *work) {(void)queue;work->queued++;}
struct sock {
 int sk_err,sk_state;unsigned int sk_shutdown;void *sk_user_data;
 int sk_peek_off;struct socket *sk_socket;bool locked;
 void (*sk_data_ready)(struct sock *);
 int sk_family;struct in6_addr sk_v6_rcv_saddr;
 struct udp_sock {u16 gso_size;} udp;
 struct inet_sock {__be32 inet_rcv_saddr;} inet;
};
static struct udp_sock *udp_sk(struct sock *sk) {return &sk->udp;}
static struct inet_sock *inet_sk(struct sock *sk) {return &sk->inet;}
struct virtio_vsock_sock {int tx_lock;u32 buf_alloc,peer_buf_alloc;};
static void spin_lock_bh(int *lock) {assert(!*lock);*lock=1;}
static void spin_unlock_bh(int *lock) {assert(*lock);*lock=0;}
struct vsock_sock {struct sock sk;unsigned int peer_shutdown;struct virtio_vsock_sock *trans;};
#define vsock_sk(socket) container_of(socket,struct vsock_sock,sk)
#define sk_vsock(socket) (&(socket)->sk)
struct virtio_vsock_pkt_info {u16 op;struct vsock_sock *vsk;};
struct socket;
struct msghdr;
struct proto_ops {
 int (*listen)(struct socket *,int);
 int (*connect)(struct socket *,struct sockaddr *,int,int);
 __poll_t (*poll)(struct file *,struct socket *,poll_table *);
 int (*recvmsg)(struct socket *,struct msghdr *,size_t,int);
 int (*set_peek_off)(struct sock *,int);
};
struct socket {struct sock *sk;int state,type;const struct proto_ops *ops;struct file *file;};
struct kvec {void *iov_base;size_t iov_len;};
struct msghdr {unsigned int msg_flags;int msg_namelen;struct iov_iter {const u8 *bytes;} msg_iter;void *msg_control;size_t msg_controllen;};
struct cmsghdr {size_t cmsg_len;int cmsg_level,cmsg_type;};
#define CMSG_ALIGN(length) (((length)+sizeof(size_t)-1)&~(sizeof(size_t)-1))
#define CMSG_LEN(length) (CMSG_ALIGN(sizeof(struct cmsghdr))+(length))
#define CMSG_SPACE(length) CMSG_ALIGN(CMSG_LEN(length))
#define CMSG_DATA(control) ((u8 *)(control)+CMSG_LEN(0))
#define CMSG_FIRSTHDR(message) ((message)->msg_controllen>=sizeof(struct cmsghdr)?(struct cmsghdr *)(message)->msg_control:NULL)
#define CMSG_OK(message,control) ((control)->cmsg_len>=sizeof(struct cmsghdr)&&(control)->cmsg_len<=(message)->msg_controllen-((u8 *)(control)-(u8 *)(message)->msg_control))
static struct cmsghdr *next_cmsg(struct msghdr *message,struct cmsghdr *control) {
 size_t offset=(u8 *)control-(u8 *)message->msg_control;
 size_t advance=CMSG_ALIGN(control->cmsg_len);
 return advance+sizeof(*control)<=message->msg_controllen-offset?(void *)((u8 *)control+advance):NULL;
}
#define for_each_cmsghdr(control,message) for((control)=CMSG_FIRSTHDR(message);(control);(control)=next_cmsg(message,control))
static int allocations,live_allocations;static bool allocation_fails;
static void *kmalloc(size_t length,int flags) {
 (void)flags;allocations++;if(allocation_fails)return NULL;
 live_allocations++;return malloc(length);
}
static void kfree(void *bytes) {assert(live_allocations>0);live_allocations--;free(bytes);}
struct sk_buff {struct sk_buff *next;unsigned int len;u8 data[4116];};
struct sk_buff_head {struct sk_buff *first,*last;unsigned int qlen;};
static bool skb_queue_empty(struct sk_buff_head *queue) {return !queue->first;}
static struct sk_buff *alloc_skb(unsigned int length,int flags) {
 assert(length<=4116);(void)flags;return calloc(1,sizeof(struct sk_buff));
}
static void skb_put_data(struct sk_buff *skb,const void *bytes,unsigned int length) {
 memcpy(skb->data,bytes,length);skb->len=length;
}
static void skb_queue_tail(struct sk_buff_head *queue,struct sk_buff *skb) {
 if(queue->last)queue->last->next=skb;else queue->first=skb;
 queue->last=skb;queue->qlen++;
}
static int shutdowns;
static int kernel_sock_shutdown(struct socket *socket,int how) {(void)socket;(void)how;shutdowns++;return 0;}
#define TERRA_HEADER_BYTES 8
#define TERRA_ENDPOINT_BYTES 20
#define TERRA_OP_TCP_OPENED 0x101
#define TERRA_OP_UDP_SEND 0x03
#define TERRA_OP_UDP_DATAGRAM 0x103
#define TERRA_OP_UDP_ERROR 0x104
#define TERRA_UDP_DATAGRAM 4096
#define TERRA_UDP_FRAME_BYTES (TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES+TERRA_UDP_DATAGRAM)
struct terra_tsi_socket {
 u8 opened[64];unsigned int opened_needed;
 struct mutex select_mutex;struct delayed_work timeout_work;struct socket *stream;
 unsigned long opening_deadline;bool connecting,closing;int connect_error;
 struct sock *sk;struct sockaddr_storage peer;bool udp_connected;int udp_failed,wait;
 u8 *udp_receive,*udp_frame;struct sk_buff_head datagrams;
 bool peer_send_closed,peer_closed,connected,udp_open;int mode;
 const struct proto_ops *native_ops;struct work_struct setup_work,udp_work;
 u8 opening[64];unsigned int opening_offset,opening_length,opened_length;
};
static void terra_finish_opening(struct terra_tsi_socket *state,int error) {
 state->connecting=false;state->connect_error=error;
}
static __poll_t carrier_poll_mask;
static __poll_t carrier_poll(struct file *file,struct socket *socket,poll_table *wait) {
 (void)file;(void)socket;(void)wait;return carrier_poll_mask;
}
static void sock_poll_wait(struct file *file,struct socket *socket,poll_table *wait) {
 (void)file;(void)socket;(void)wait;
}
static int state_poll_registrations;
static int *state_poll_queue;
static void poll_wait(struct file *file,int *queue,poll_table *wait) {
 (void)file;if(wait) {state_poll_registrations++;state_poll_queue=queue;}
}
static struct terra_tsi_socket *terra_socket_state(struct socket *socket) {return socket->sk->sk_user_data;}
static struct sock *peek_locked_carrier;
static int sk_set_peek_off(struct sock *sk,int offset) {
 if(sk==peek_locked_carrier)assert(sk->locked);
 WRITE_ONCE(sk->sk_peek_off,offset);return 0;
}
static void lock_sock(struct sock *sk) {assert(!sk->locked);sk->locked=true;}
static void release_sock(struct sock *sk) {assert(sk->locked);sk->locked=false;}
static int carrier_set_peek_off(struct sock *sk,int offset) {
 lock_sock(sk);int result=sk_set_peek_off(sk,offset);release_sock(sk);return result;
}
static void terra_stream_options(struct terra_tsi_socket *state) {(void)state;}
static int native_result,native_receive_flags,native_receive_calls;
static int native_receive(struct socket *socket,struct msghdr *message,size_t length,int flags) {
 (void)socket;(void)message;(void)length;native_receive_flags=flags;native_receive_calls++;return native_result;
}
static int wakes,queued_errors,sends,waits,wait_action;
static struct sock *waiting_socket;
static u8 carrier[270000];static s64 carrier_available,carrier_space;
static int credit_requests,credit_request_error;
static s64 requested_credit_space=-1;
static int virtio_transport_send_pkt_info(struct vsock_sock *socket,struct virtio_vsock_pkt_info *info) {
 assert(socket->sk.locked&&!socket->trans->tx_lock);
 assert(info->vsk==socket&&info->op==VIRTIO_VSOCK_OP_CREDIT_REQUEST);
 credit_requests++;
 if(!credit_request_error&&requested_credit_space>=0)carrier_space=requested_credit_space;
 return credit_request_error;
}
static s64 vsock_stream_has_data(struct vsock_sock *sk) {(void)sk;return carrier_available;}
static s64 vsock_stream_has_space(struct vsock_sock *sk) {(void)sk;return carrier_space;}
static int kernel_recvmsg(struct socket *socket,struct msghdr *message,struct kvec *vector,
 unsigned int count,size_t length,int flags) {
 (void)socket;(void)message;assert(count==1&&length==vector->iov_len);
 if(!carrier_available)return -EAGAIN;
 assert(carrier_available>=(s64)length);memcpy(vector->iov_base,carrier,length);
 if(!(flags&MSG_PEEK)) {carrier_available-=length;memmove(carrier,carrier+length,carrier_available);}
 return length;
}
static int kernel_sendmsg(struct socket *socket,struct msghdr *message,struct kvec *vector,
 unsigned int count,size_t length) {
 (void)socket;(void)message;assert(count==1&&length==vector->iov_len);sends++;
 assert(length<=sizeof(carrier));memcpy(carrier,vector->iov_base,length);return length;
}
static void terra_socket_wake(struct terra_tsi_socket *state) {(void)state;wakes++;}
static int decoded_data_wakes;
static void decoded_data_ready(struct sock *sk) {assert(sk);decoded_data_wakes++;}
static void terra_socket_error(struct terra_tsi_socket *state,int error) {state->sk->sk_err=-error;terra_socket_wake(state);}
static void terra_queue_datagram_error(struct terra_tsi_socket *state,int error,const struct sockaddr_storage *peer) {
 (void)state;assert(error==-EACCES&&peer->ss_family==AF_INET);queued_errors++;
}
static void terra_udp_failed(struct terra_tsi_socket *state,int error) {state->udp_failed=error;terra_socket_error(state,error);}
static int sock_error(struct sock *socket) {int error=socket->sk_err;socket->sk_err=0;return -error;}
static long sock_sndtimeo(struct sock *socket,bool nonblock) {(void)socket;return nonblock?0:30;}
static int sock_intr_errno(long timeout) {(void)timeout;return -EINTR;}
static size_t iter_copy_limit=SIZE_MAX;
static bool copy_from_iter_full(void *destination,size_t length,struct iov_iter *source) {
 if(length>iter_copy_limit)return false;
 iter_copy_limit-=length;
 memcpy(destination,source->bytes,length);source->bytes+=length;return true;
}
static void apply_wait_event(void) {
 waits++;
 if(wait_action==1)waiting_socket->sk_shutdown=SEND_SHUTDOWN;
 else if(wait_action==2)waiting_socket->sk_err=EACCES;
 else carrier_space=10000;
}
#define wait_event_interruptible_timeout(queue,condition,timeout) \
 ({assert((queue)==123);(void)(timeout);if(!(condition)){apply_wait_event();assert(condition);}1L;})
'''

CHECKS = r'''
static void peer_checks(void) {
 struct sockaddr_storage peer={0},decoded;
 struct sockaddr_in *ipv4=(void *)&peer;
 u8 endpoint[TERRA_ENDPOINT_BYTES];
 ipv4->sin_family=AF_INET;ipv4->sin_port=htons(443);ipv4->sin_addr.s_addr=htonl(0xcb007101);
 assert(!terra_encode_peer(endpoint,&peer,sizeof(struct sockaddr_in)));
 u8 expected[TERRA_ENDPOINT_BYTES]={4,0,0xbb,1,203,0,113,1};
 assert(!memcmp(endpoint,expected,sizeof(expected)));
 assert(terra_decode_peer(&decoded,endpoint)==sizeof(struct sockaddr_in));
 assert(terra_peer_equal(&peer,&decoded));
 endpoint[8]=1;assert(terra_decode_peer(&decoded,endpoint)==-EPROTO);endpoint[8]=0;
 endpoint[1]=1;assert(terra_decode_peer(&decoded,endpoint)==-EPROTO);endpoint[1]=0;
 endpoint[0]=5;assert(terra_decode_peer(&decoded,endpoint)==-EPROTO);
 ipv4->sin_port=0;assert(terra_encode_peer(endpoint,&peer,sizeof(struct sockaddr_in))==-EINVAL);
 ipv4->sin_port=htons(443);
 struct sockaddr_storage mapped={0};
 struct sockaddr_in6 *ipv6=(void *)&mapped;
 ipv6->sin6_family=AF_INET6;ipv6->sin6_port=htons(443);
 ipv6->sin6_addr.s6_addr32[2]=htonl(0xffff);ipv6->sin6_addr.s6_addr32[3]=htonl(0xcb007101);
 assert(terra_peer_equal(&peer,&mapped)&&terra_peer_equal(&mapped,&peer));
 ipv6->sin6_port=htons(444);assert(!terra_peer_equal(&peer,&mapped));
 ipv6->sin6_port=htons(443);ipv6->sin6_scope_id=1;
 assert(terra_encode_peer(endpoint,&mapped,sizeof(struct sockaddr_in6))==-EOPNOTSUPP);
}

static void error_checks(void) {
 assert(terra_decode_error(1)==-EACCES&&terra_decode_error(10)==-ECONNREFUSED);
 assert(terra_decode_error(11)==-ECONNRESET&&terra_decode_error(19)==-ENETDOWN);
 assert(terra_decode_error(20)==-EPROTO&&terra_decode_error(21)==-EPROTO&&terra_decode_error(0)==-EPROTO);
}

static void opening_checks(void) {
 struct terra_tsi_socket state={.opened_needed=32};
 u8 opened[32]={0x01,0x01,0,0,24,0,0,0, 0,0,0,0, 4,0,0xbb,1,203,0,113,1};
 memcpy(state.opened,opened,sizeof(opened));
 assert(!terra_validate_opened(&state));
 unsigned int corrupt[]={0,1,2,10,13,20};
 for(unsigned int i=0;i<ARRAY_SIZE(corrupt);i++) {
  state.opened[corrupt[i]]^=1;assert(terra_validate_opened(&state)==-EPROTO);state.opened[corrupt[i]]^=1;
 }
 put_unaligned_le16(1,state.opened+8);assert(terra_validate_opened(&state)==-EPROTO);
 state.opened_needed=12;assert(terra_validate_opened(&state)==-EACCES);
 put_unaligned_le16(0,state.opened+8);assert(terra_validate_opened(&state)==-EPROTO);
 state.connecting=true;state.opening_deadline=2000;jiffies=1000;
 terra_open_timeout(&state.timeout_work.work);
 assert(state.connecting&&!state.connect_error&&timeout_delay==1000&&state.timeout_work.work.queued==1);
 jiffies=2000;terra_open_timeout(&state.timeout_work.work);
 assert(!state.connecting&&state.connect_error==-ETIMEDOUT&&shutdowns==1);
 state.connecting=true;state.connect_error=0;state.opening_deadline=3;jiffies=ULONG_MAX-2;
 terra_open_timeout(&state.timeout_work.work);
 assert(state.connecting&&!state.connect_error&&timeout_delay==6);
 state.closing=true;jiffies=3;terra_open_timeout(&state.timeout_work.work);
 assert(state.connecting&&!state.connect_error);
}
static void clear_datagrams(struct sk_buff_head *queue) {
 while(queue->first) {struct sk_buff *next=queue->first->next;free(queue->first);queue->first=next;}
 memset(queue,0,sizeof(*queue));
}

static void check_udp_resume(struct terra_tsi_socket *state,bool needed) {
 struct socket outer={.sk=state->sk,.type=SOCK_DGRAM};struct msghdr message={0};
 state->sk->sk_user_data=state;
 state->udp_work.queued=0;terra_resume_udp(state);
 assert(state->udp_work.queued==(needed?1:0));
 state->udp_work.queued=0;resume_external_receive(state,true);
 assert(state->udp_work.queued==(needed?1:0));
 state->udp_work.queued=0;resume_external_receive(state,false);assert(!state->udp_work.queued);
 const int results[]={0,1,-EFAULT,-EAGAIN};
 for(unsigned int i=0;i<ARRAY_SIZE(results);i++) {
  native_result=results[i];
  const int flags[]={0,MSG_PEEK,MSG_DONTWAIT,MSG_PEEK|MSG_DONTWAIT};
  for(unsigned int f=0;f<ARRAY_SIZE(flags);f++) {
   native_receive_calls=0;state->udp_work.queued=0;
   assert(receive_native_once(&outer,&message,0,flags[f])==native_result);
   assert(native_receive_calls==1&&native_receive_flags==(flags[f]|MSG_DONTWAIT));
   assert(state->udp_work.queued==(needed?1:0));
   native_receive_calls=0;state->udp_work.queued=0;
   assert(receive_error_queue(&outer,&message,0,flags[f]|MSG_ERRQUEUE)==native_result);
   assert(native_receive_calls==1&&native_receive_flags==(flags[f]|MSG_ERRQUEUE));
   assert(state->udp_work.queued==(needed?1:0));
  }
 }
 const int options[][2]={{SOL_SOCKET,SO_RCVBUF},{SOL_IP,IP_RECVERR},{SOL_IPV6,IPV6_RECVERR}};
 for(unsigned int i=0;i<ARRAY_SIZE(options);i++) {
  state->udp_work.queued=0;
  assert(!resume_receive_config(&outer,0,options[i][0],options[i][1]));
  assert(state->udp_work.queued==(needed?1:0));
  state->udp_work.queued=0;
  assert(resume_receive_config(&outer,-EFAULT,options[i][0],options[i][1])==-EFAULT);
  assert(!state->udp_work.queued);
 }
 state->udp_work.queued=0;
 assert(!resume_receive_config(&outer,0,SOL_SOCKET,SO_SNDBUF));
 assert(!resume_receive_config(&outer,0,SOL_IP,IP_TTL));
 assert(!state->udp_work.queued);
}
static void udp_resume_checks(void) {
 struct vsock_sock transport={.sk.sk_state=TCP_ESTABLISHED};struct sock outer={0};
 struct socket socket={.sk=&transport.sk};
 struct proto_ops native={.poll=carrier_poll,.recvmsg=native_receive};
 struct terra_tsi_socket state={.stream=&socket,.sk=&outer,.udp_open=true,.native_ops=&native};
 carrier_poll_mask=EPOLLIN;
 for(carrier_available=0;carrier_available<TERRA_HEADER_BYTES;carrier_available++)
  check_udp_resume(&state,false);
 carrier_available=TERRA_HEADER_BYTES;check_udp_resume(&state,true);
 carrier_available=0;transport.sk.sk_err=EIO;check_udp_resume(&state,true);
 transport.sk.sk_err=0;transport.sk.sk_state=TCP_CLOSE;check_udp_resume(&state,true);
 transport.sk.sk_state=TCP_ESTABLISHED;transport.sk.sk_shutdown=RCV_SHUTDOWN;
 check_udp_resume(&state,true);transport.sk.sk_shutdown=0;transport.peer_shutdown=SEND_SHUTDOWN;
 for(carrier_available=0;carrier_available<TERRA_HEADER_BYTES;carrier_available++)
  check_udp_resume(&state,true);
 transport.peer_shutdown=0;carrier_available=0;check_udp_resume(&state,false);
 state.udp_open=false;state.stream=NULL;carrier_available=TERRA_HEADER_BYTES;
 state.udp_work.queued=0;terra_resume_udp(&state);resume_external_receive(&state,true);
 assert(!state.udp_work.queued);
 struct socket native_socket={.sk=&outer,.type=SOCK_DGRAM};struct msghdr message={0};
 native_result=-EFAULT;native_receive_calls=0;
 assert(receive_error_queue(&native_socket,&message,0,MSG_ERRQUEUE|MSG_DONTWAIT)==-EFAULT);
 assert(native_receive_calls==1&&native_receive_flags==(MSG_ERRQUEUE|MSG_DONTWAIT));
 assert(!state.udp_work.queued);
 assert(!resume_receive_config(&native_socket,0,SOL_SOCKET,SO_RCVBUF));
 assert(!state.udp_work.queued);
}

static void udp_checks(void) {
 struct virtio_vsock_sock capacity={.buf_alloc=24576,.peer_buf_alloc=24576};
 struct vsock_sock transport={.sk.sk_state=TCP_ESTABLISHED,.trans=&capacity};
 struct sock outer={.sk_data_ready=decoded_data_ready};
 struct socket socket={.sk=&transport.sk};u8 received[4124],outgoing[4124];
 struct terra_tsi_socket state={.sk=&outer,.stream=&socket,.udp_receive=received,.udp_frame=outgoing,.wait=123};
 struct sockaddr_storage peer={0};struct sockaddr_in *address=(void *)&peer;
 address->sin_family=AF_INET;address->sin_port=htons(80);address->sin_addr.s_addr=htonl(0xcb007101);
 u8 frame[32]={0};terra_frame_header(frame,TERRA_OP_UDP_DATAGRAM,21);
 assert(!terra_encode_peer(frame+8,&peer,sizeof(*address)));frame[28]='D';
 memcpy(carrier,frame,29);carrier_available=10;
 assert(!terra_receive_udp_frame(&state)&&!state.udp_failed&&carrier_available==10);
 int before_delivery_wakes=wakes;
 int before_data_wakes=decoded_data_wakes;
 carrier_available=29;assert(terra_receive_udp_frame(&state)&&state.datagrams.qlen==1);
 assert(decoded_data_wakes==before_data_wakes+1&&wakes==before_delivery_wakes);
 assert(state.datagrams.first->len==21&&state.datagrams.first->data[20]=='D');clear_datagrams(&state.datagrams);
 memcpy(carrier,frame,29);memcpy(carrier+29,frame,29);carrier_available=58;
 assert(terra_receive_udp_frame(&state)&&terra_receive_udp_frame(&state)&&state.datagrams.qlen==2);
 assert(decoded_data_wakes==before_data_wakes+3&&wakes==before_delivery_wakes);
 assert(!terra_receive_udp_frame(&state)&&!state.udp_failed);clear_datagrams(&state.datagrams);
 outer.sk_shutdown=RCV_SHUTDOWN;memcpy(carrier,frame,29);carrier_available=29;
 assert(terra_receive_udp_frame(&state)&&!state.datagrams.qlen);
 assert(decoded_data_wakes==before_data_wakes+3&&wakes==before_delivery_wakes);outer.sk_shutdown=0;
 for(unsigned int available=0;available<29;available++) {
  memcpy(carrier,frame,29);carrier_available=available;transport.peer_shutdown=SEND_SHUTDOWN;
  assert(!terra_receive_udp_frame(&state));
  assert(state.udp_failed==(available?-EPROTO:-ENETDOWN));state.udp_failed=0;outer.sk_err=0;
 }
 transport.peer_shutdown=0;terra_frame_header(frame,TERRA_OP_UDP_ERROR,24);
 put_unaligned_le16(1,frame+8);put_unaligned_le16(0,frame+10);
 assert(!terra_encode_peer(frame+12,&peer,sizeof(*address)));memcpy(carrier,frame,32);carrier_available=32;
 int before_queued_error_wakes=wakes;
 assert(terra_receive_udp_frame(&state)&&outer.sk_err==EACCES&&queued_errors==1);
 assert(wakes==before_queued_error_wakes+1);
 struct msghdr message={.msg_iter.bytes=(const u8 *)"abc"};carrier_space=0;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,3,0,true)==-EACCES&&!outer.sk_err&&!sends);
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,3,0,true)==-EAGAIN&&!sends);
 for(wait_action=1;wait_action<=2;wait_action++) {
  outer.sk_shutdown=0;message.msg_iter.bytes=(const u8 *)"abc";waiting_socket=&outer;
  int expected=wait_action==1?-EPIPE:-EACCES;
  assert(terra_send_udp(&state,&peer,sizeof(*address),&message,3,0,false)==expected&&!sends);
 }
 assert(waits==2&&!outer.sk_err);outer.sk_shutdown=0;wait_action=0;message.msg_iter.bytes=(const u8 *)"abc";
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,3,0,false)==3&&sends==1&&waits==3);
 assert(get_unaligned_le16(carrier)==TERRA_OP_UDP_SEND&&get_unaligned_le32(carrier+4)==23&&!memcmp(carrier+28,"abc",3));
 terra_frame_header(frame,TERRA_OP_UDP_ERROR,24);put_unaligned_le16(21,frame+8);
 memcpy(carrier,frame,32);carrier_available=32;
 int before_error_wakes=wakes;
 assert(!terra_receive_udp_frame(&state)&&state.udp_failed==-EPROTO);state.udp_failed=0;
 assert(wakes==before_error_wakes+1);
 terra_frame_header(frame,TERRA_OP_UDP_DATAGRAM,4117);memcpy(carrier,frame,8);carrier_available=8;
 assert(!terra_receive_udp_frame(&state)&&state.udp_failed==-EPROTO);
}
static void udp_control_checks(void) {
 struct sock sk={.sk_family=AF_INET,.udp.gso_size=1200};u16 segment;
 union {struct cmsghdr alignment;u8 bytes[128];} control={0};
 struct msghdr message={0};
 assert(!terra_udp_control(&sk,&message,&segment)&&segment==1200);
 assert(!check_udp_send_validation(&sk,&message,64*1200));
 assert(check_udp_send_validation(&sk,&message,64*1200+1)==-EINVAL);
 sk.udp.gso_size=0;
 assert(!check_udp_send_validation(&sk,&message,TERRA_UDP_DATAGRAM));
 assert(check_udp_send_validation(&sk,&message,TERRA_UDP_DATAGRAM+1)==-EMSGSIZE);
 sk.udp.gso_size=TERRA_UDP_DATAGRAM+1;
 assert(check_udp_send_validation(&sk,&message,1)==-EINVAL);sk.udp.gso_size=1200;
 message.msg_control=control.bytes;message.msg_controllen=sizeof(struct cmsghdr)-1;
 assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 struct cmsghdr *entry=(void *)control.bytes;
 entry->cmsg_level=SOL_UDP;entry->cmsg_type=UDP_SEGMENT;
 entry->cmsg_len=CMSG_LEN(sizeof(u16));message.msg_controllen=CMSG_SPACE(sizeof(u16));
 const u16 invalid_segments[]={0,TERRA_UDP_DATAGRAM+1};
 for(unsigned int i=0;i<ARRAY_SIZE(invalid_segments);i++) {
  memcpy(CMSG_DATA(entry),&invalid_segments[i],sizeof(u16));
  assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 }
 u16 override=1000;memcpy(CMSG_DATA(entry),&override,sizeof(override));
 assert(!terra_udp_control(&sk,&message,&segment)&&segment==override);
 assert(!check_udp_send_validation(&sk,&message,64*1000));
 assert(check_udp_send_validation(&sk,&message,64*1000+1)==-EINVAL);
 entry->cmsg_len=CMSG_LEN(sizeof(u16)+1);
 assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 entry->cmsg_len=sizeof(control.bytes)+1;
 assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 entry->cmsg_level=SOL_IP;entry->cmsg_type=IP_TOS;
 int ecn=2;memcpy(CMSG_DATA(entry),&ecn,sizeof(ecn));
 entry->cmsg_len=CMSG_LEN(sizeof(u8));message.msg_controllen=CMSG_SPACE(sizeof(u8));
 assert(!terra_udp_control(&sk,&message,&segment)&&segment==1200);
 entry->cmsg_len=CMSG_LEN(sizeof(ecn));message.msg_controllen=CMSG_SPACE(sizeof(ecn));
 assert(!terra_udp_control(&sk,&message,&segment));
 const int invalid_tos[]={-1,256};
 for(unsigned int i=0;i<ARRAY_SIZE(invalid_tos);i++) {
  memcpy(CMSG_DATA(entry),&invalid_tos[i],sizeof(int));
  assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 }
 entry->cmsg_len=CMSG_LEN(0);assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 entry->cmsg_level=SOL_IPV6;entry->cmsg_type=IPV6_TCLASS;
 entry->cmsg_len=CMSG_LEN(sizeof(int));ecn=-1;memcpy(CMSG_DATA(entry),&ecn,sizeof(ecn));
 assert(!terra_udp_control(&sk,&message,&segment));
 ecn=256;memcpy(CMSG_DATA(entry),&ecn,sizeof(ecn));
 assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 entry->cmsg_level=0x7fff;assert(terra_udp_control(&sk,&message,&segment)==-EOPNOTSUPP);
 entry->cmsg_level=SOL_IP;entry->cmsg_type=IP_PKTINFO;
 entry->cmsg_len=CMSG_LEN(sizeof(struct in_pktinfo));message.msg_controllen=CMSG_SPACE(sizeof(struct in_pktinfo));
 struct in_pktinfo packet={0};memcpy(CMSG_DATA(entry),&packet,sizeof(packet));
 assert(!terra_udp_control(&sk,&message,&segment));
 packet.ipi_ifindex=1;memcpy(CMSG_DATA(entry),&packet,sizeof(packet));
 assert(terra_udp_control(&sk,&message,&segment)==-EOPNOTSUPP);packet.ipi_ifindex=0;
 sk.inet.inet_rcv_saddr=htonl(0xc0000201);packet.ipi_spec_dst.s_addr=sk.inet.inet_rcv_saddr;
 memcpy(CMSG_DATA(entry),&packet,sizeof(packet));assert(!terra_udp_control(&sk,&message,&segment));
 packet.ipi_spec_dst.s_addr=htonl(0xc0000202);memcpy(CMSG_DATA(entry),&packet,sizeof(packet));
 assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 entry->cmsg_level=SOL_IPV6;entry->cmsg_type=IPV6_PKTINFO;
 entry->cmsg_len=CMSG_LEN(sizeof(struct in6_pktinfo));message.msg_controllen=CMSG_SPACE(sizeof(struct in6_pktinfo));
 struct in6_pktinfo packet6={0};memcpy(CMSG_DATA(entry),&packet6,sizeof(packet6));
 assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);sk.sk_family=AF_INET6;
 assert(!terra_udp_control(&sk,&message,&segment));
 packet6.ipi6_ifindex=1;memcpy(CMSG_DATA(entry),&packet6,sizeof(packet6));
 assert(terra_udp_control(&sk,&message,&segment)==-EOPNOTSUPP);packet6.ipi6_ifindex=0;
 sk.sk_v6_rcv_saddr.s6_addr[15]=1;packet6.ipi6_addr=sk.sk_v6_rcv_saddr;
 memcpy(CMSG_DATA(entry),&packet6,sizeof(packet6));assert(!terra_udp_control(&sk,&message,&segment));
 packet6.ipi6_addr.s6_addr[15]=2;memcpy(CMSG_DATA(entry),&packet6,sizeof(packet6));
 assert(terra_udp_control(&sk,&message,&segment)==-EINVAL);
 memset(control.bytes,0,sizeof(control.bytes));
 entry->cmsg_level=SOL_IP;entry->cmsg_type=IP_TOS;entry->cmsg_len=CMSG_LEN(sizeof(u8));
 *CMSG_DATA(entry)=2;
 struct cmsghdr *second=(void *)(control.bytes+CMSG_SPACE(sizeof(u8)));
 second->cmsg_level=SOL_UDP;second->cmsg_type=UDP_SEGMENT;second->cmsg_len=CMSG_LEN(sizeof(u16));
 memcpy(CMSG_DATA(second),&override,sizeof(override));
 message.msg_controllen=CMSG_SPACE(sizeof(u8))+CMSG_SPACE(sizeof(u16));
 assert(!terra_udp_control(&sk,&message,&segment)&&segment==override);
 second->cmsg_level=0x7fff;assert(terra_udp_control(&sk,&message,&segment)==-EOPNOTSUPP);
}
static void udp_receive_shutdown_checks(void) {
 struct sock sk={0};struct proto_ops native={.poll=carrier_poll};
 struct socket socket={.sk=&sk};
 struct terra_tsi_socket state={.sk=&sk,.native_ops=&native};
 carrier_poll_mask=0;
 assert(!udp_receive_ready(&state,&socket));
 sk.sk_shutdown=SEND_SHUTDOWN;
 assert(!udp_receive_ready(&state,&socket));
 sk.sk_shutdown=RCV_SHUTDOWN;
 assert(udp_receive_ready(&state,&socket));
}
static int native_listen_result,native_listens,native_connects;
static struct terra_tsi_socket *selecting_state;
static int native_listen(struct socket *socket,int backlog) {
 struct terra_tsi_socket *state=terra_socket_state(socket);
 assert(state->select_mutex.locked&&backlog==7);native_listens++;
 return native_listen_result;
}
static int native_connect(struct socket *socket,struct sockaddr *peer,int length,int flags) {
 (void)peer;(void)length;(void)flags;
 assert(terra_socket_state(socket)->select_mutex.locked);native_connects++;return -EISCONN;
}
static void finish_listen_before_connect_lock(void) {selecting_state->mode=TERRA_SOCKET_NATIVE;}
static void listen_selection_checks(void) {
 struct sock sk={0};struct proto_ops native={.listen=native_listen,.connect=native_connect};
 struct socket socket={.sk=&sk,.type=SOCK_STREAM};struct sockaddr peer={.sa_family=AF_INET};
 struct terra_tsi_socket state={.sk=&sk,.native_ops=&native};sk.sk_user_data=&state;
 native_listen_result=-EADDRINUSE;
 assert(terra_listen(&socket,7)==-EADDRINUSE&&!state.mode&&!state.select_mutex.locked&&native_listens==1);
 native_listen_result=0;
 assert(!terra_listen(&socket,7)&&state.mode==TERRA_SOCKET_NATIVE&&!state.select_mutex.locked&&native_listens==2);
 state.mode=TERRA_SOCKET_EXTERNAL;
 assert(terra_listen(&socket,7)==-EOPNOTSUPP&&state.mode==TERRA_SOCKET_EXTERNAL&&!state.select_mutex.locked&&native_listens==2);
 state.mode=0;select_lock_error=-EINTR;
 assert(terra_listen(&socket,7)==-EINTR&&!state.mode&&!state.select_mutex.locked&&native_listens==2);
 select_lock_error=0;selecting_state=&state;select_lock_hook=finish_listen_before_connect_lock;
 assert(connect_native_after_lock(&socket,&peer,sizeof(peer),0)==-EISCONN);
 assert(native_connects==1&&state.mode==TERRA_SOCKET_NATIVE&&!state.select_mutex.locked);
}

static void check_udp_frames(const struct sockaddr_storage *peer,const u8 *payload,size_t length,u16 segment) {
 u8 endpoint[TERRA_ENDPOINT_BYTES];
 unsigned int peer_length=peer->ss_family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
 assert(!terra_encode_peer(endpoint,peer,peer_length));
 size_t remaining=length,offset=0,copied=0;
 do {
  size_t bytes=segment?min_t(size_t,remaining,segment):remaining;
  assert(get_unaligned_le16(carrier+offset)==TERRA_OP_UDP_SEND);
  assert(!get_unaligned_le16(carrier+offset+2));
  assert(get_unaligned_le32(carrier+offset+4)==TERRA_ENDPOINT_BYTES+bytes);
  assert(!memcmp(carrier+offset+TERRA_HEADER_BYTES,endpoint,sizeof(endpoint)));
  assert(!memcmp(carrier+offset+TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES,payload+copied,bytes));
  offset+=TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES+bytes;remaining-=bytes;copied+=bytes;
 } while(remaining);
 unsigned int count=segment?max_t(size_t,1,DIV_ROUND_UP(length,segment)):1;
 assert(offset==length+count*(TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES));
}

static void udp_gso_checks(void) {
 struct virtio_vsock_sock capacity={.buf_alloc=24576,.peer_buf_alloc=24576};
 struct vsock_sock transport={.sk.sk_state=TCP_ESTABLISHED,.trans=&capacity};
 struct sock outer={0};struct socket socket={.sk=&transport.sk};u8 outgoing[TERRA_UDP_FRAME_BYTES];
 struct terra_tsi_socket state={.sk=&outer,.stream=&socket,.udp_frame=outgoing,.wait=123};
 struct sockaddr_storage peer={0};struct sockaddr_in *address=(void *)&peer;
 address->sin_family=AF_INET;address->sin_port=htons(80);address->sin_addr.s_addr=htonl(0xcb007101);
 u8 payload[8193];for(unsigned int i=0;i<sizeof(payload);i++)payload[i]=i%251;
 const size_t exact_buffer_payload=TERRA_UDP_FRAME_BYTES-2*(TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES);
 const struct {size_t length;u16 segment;bool uses_heap;} cases[]={
  {0,0,false},{0,1200,false},{7,1200,false},{4096,0,false},{3600,1200,false},
  {6000,1200,true},{2401,1000,false},{8193,4096,true},{64,1,false},
  {exact_buffer_payload,TERRA_UDP_DATAGRAM/2,false},
  {exact_buffer_payload+1,TERRA_UDP_DATAGRAM/2,true}
 };
 for(unsigned int i=0;i<ARRAY_SIZE(cases);i++) {
  struct msghdr message={.msg_iter.bytes=payload};carrier_space=10000;
  int before_sends=sends,before_allocations=allocations;
  assert(terra_send_udp(&state,&peer,sizeof(*address),&message,cases[i].length,cases[i].segment,true)==(int)cases[i].length);
  assert(sends==before_sends+1&&message.msg_iter.bytes==payload+cases[i].length);
  assert(allocations==before_allocations+cases[i].uses_heap);
  assert(!live_allocations&&!capacity.tx_lock);
  check_udp_frames(&peer,payload,cases[i].length,cases[i].segment);
 }
 size_t framed=2401+3*(TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES);
 struct msghdr message={.msg_iter.bytes=payload};int before_sends=sends,before_allocations=allocations;
 carrier[0]=0xa5;carrier_space=framed-1;
 int before_requests=credit_requests;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,2401,1000,true)==-EAGAIN);
 assert(sends==before_sends&&allocations==before_allocations&&message.msg_iter.bytes==payload&&carrier[0]==0xa5);
 assert(credit_requests==before_requests+1&&!transport.sk.locked);
 capacity.buf_alloc=framed-1;capacity.peer_buf_alloc=framed;carrier_space=10000;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,2401,1000,true)==-EMSGSIZE);
 capacity.buf_alloc=framed;capacity.peer_buf_alloc=framed-1;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,2401,1000,false)==-EMSGSIZE);
 assert(sends==before_sends&&allocations==before_allocations&&message.msg_iter.bytes==payload&&carrier[0]==0xa5);
 assert(credit_requests==before_requests+1);
 capacity.peer_buf_alloc=framed;carrier_space=framed;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,2401,1000,true)==2401&&sends==before_sends+1);
 check_udp_frames(&peer,payload,2401,1000);
 capacity.buf_alloc=capacity.peer_buf_alloc=24576;carrier_space=framed-1;message.msg_iter.bytes=payload;
 int before_waits=waits;waiting_socket=&outer;wait_action=0;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,2401,1000,false)==2401);
 assert(waits==before_waits+1&&sends==before_sends+2);check_udp_frames(&peer,payload,2401,1000);
 assert(credit_requests==before_requests+2&&!transport.sk.locked);
 message.msg_iter.bytes=payload;before_sends=sends;before_allocations=allocations;
 carrier[0]=0xa5;allocation_fails=true;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,6000,1200,true)==-ENOMEM);
 assert(sends==before_sends&&allocations==before_allocations+1&&
  message.msg_iter.bytes==payload&&!live_allocations&&carrier[0]==0xa5);allocation_fails=false;
 before_allocations=allocations;iter_copy_limit=1000;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,2401,1000,true)==-EFAULT);
 assert(sends==before_sends&&allocations==before_allocations&&
  message.msg_iter.bytes==payload+1000&&!live_allocations&&carrier[0]==0xa5);
 message.msg_iter.bytes=payload;iter_copy_limit=1200;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,6000,1200,true)==-EFAULT);
 assert(sends==before_sends&&allocations==before_allocations+1&&
  message.msg_iter.bytes==payload+1200&&!live_allocations&&carrier[0]==0xa5);iter_copy_limit=SIZE_MAX;
 transport.trans=NULL;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,2401,1000,true)==-ENETDOWN&&sends==before_sends);
}

static void udp_atomic_credit_checks(void) {
 const unsigned int peer_capacity=48*1024,framed=40*(1200+TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES);
 struct virtio_vsock_sock capacity={.buf_alloc=64*1024,.peer_buf_alloc=peer_capacity};
 struct vsock_sock transport={.sk.sk_state=TCP_ESTABLISHED,.trans=&capacity};
 struct sock outer={0};struct socket socket={.sk=&transport.sk};u8 outgoing[TERRA_UDP_FRAME_BYTES];
 struct terra_tsi_socket state={.sk=&outer,.stream=&socket,.udp_frame=outgoing,.wait=123};
 struct sockaddr_storage peer={0};struct sockaddr_in *address=(void *)&peer;
 address->sin_family=AF_INET;address->sin_port=htons(80);address->sin_addr.s_addr=htonl(0xcb007101);
 u8 payload[40*1200];for(unsigned int i=0;i<sizeof(payload);i++)payload[i]=i%251;
 struct msghdr message={.msg_iter.bytes=payload};
 int before_sends=sends,before_allocations=allocations,before_requests=credit_requests,before_waits=waits;
 carrier_space=peer_capacity-(7+TERRA_HEADER_BYTES+TERRA_ENDPOINT_BYTES);carrier[0]=0xa5;
 assert(carrier_space==framed-3);
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,sizeof(payload),1200,true)==-EAGAIN);
 assert(credit_requests==before_requests+1&&sends==before_sends&&allocations==before_allocations);
 assert(message.msg_iter.bytes==payload&&carrier[0]==0xa5&&!transport.sk.locked);
 credit_request_error=-ENOMEM;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,sizeof(payload),1200,false)==-ENOMEM);
 assert(credit_requests==before_requests+2&&sends==before_sends&&allocations==before_allocations&&waits==before_waits);
 assert(message.msg_iter.bytes==payload&&carrier[0]==0xa5&&!transport.sk.locked);
 credit_request_error=0;requested_credit_space=peer_capacity;
 assert(terra_send_udp(&state,&peer,sizeof(*address),&message,sizeof(payload),1200,false)==(int)sizeof(payload));
 assert(credit_requests==before_requests+3&&sends==before_sends+1&&allocations==before_allocations+1);
 assert(waits==before_waits&&!transport.sk.locked&&!live_allocations);
 check_udp_frames(&peer,payload,sizeof(payload),1200);requested_credit_space=-1;
 transport.sk.sk_state=TCP_CLOSE;
 assert(virtio_transport_send_credit_request(&transport)==-ENOTCONN);
 assert(credit_requests==before_requests+3&&!transport.sk.locked);
}
static void udp_poll_checks(void) {
 struct vsock_sock transport={.sk.sk_state=TCP_ESTABLISHED};struct sock outer={0};
 struct proto_ops native={.poll=carrier_poll};struct socket stream={.sk=&transport.sk};
 struct socket socket={.sk=&outer,.type=SOCK_DGRAM};poll_table wait={0};
 struct terra_tsi_socket state={.sk=&outer,.stream=&stream,.native_ops=&native,.mode=TERRA_SOCKET_EXTERNAL};
 outer.sk_user_data=&state;state_poll_registrations=0;carrier_poll_mask=EPOLLOUT|EPOLLWRNORM;carrier_space=0;
 assert(terra_socket_poll(NULL,&socket,&wait)==carrier_poll_mask);
 assert(state_poll_registrations==1&&state_poll_queue==&state.wait);
 state.udp_open=true;
 assert(!terra_socket_poll(NULL,&socket,NULL)&&state_poll_registrations==1);
 carrier_space=TERRA_UDP_FRAME_BYTES;
 assert(terra_socket_poll(NULL,&socket,NULL)==carrier_poll_mask&&state_poll_registrations==1);
 carrier_space=0;carrier_poll_mask=EPOLLIN;
 assert(terra_socket_poll(NULL,&socket,NULL)==EPOLLIN);
 carrier_poll_mask=0;struct sk_buff datagram={0};state.datagrams.first=&datagram;
 assert(terra_socket_poll(NULL,&socket,NULL)==(EPOLLIN|EPOLLRDNORM));state.datagrams.first=NULL;
 outer.sk_err=ENETDOWN;
 assert(terra_socket_poll(NULL,&socket,NULL)==EPOLLERR);
 assert(sock_error(&outer)==-ENETDOWN);state.udp_failed=-ENETDOWN;
 assert(terra_socket_poll(NULL,&socket,NULL)==(EPOLLERR|EPOLLHUP));
 assert(terra_socket_poll(NULL,&socket,NULL)==(EPOLLERR|EPOLLHUP));
}
static void tcp_close_checks(void) {
 struct vsock_sock transport={.sk.sk_state=TCP_ESTABLISHED};struct sock outer={0};
 struct proto_ops ops={.poll=carrier_poll};
 struct socket socket={.sk=&transport.sk,.ops=&ops},original={.sk=&outer,.type=SOCK_STREAM};
 struct terra_tsi_socket state={.sk=&outer,.stream=&socket,.mode=TERRA_SOCKET_EXTERNAL,.connected=true};
 outer.sk_user_data=&state;carrier_poll_mask=EPOLLIN;
 transport.peer_shutdown=SEND_SHUTDOWN;terra_track_tcp_close(&state,&transport.sk);
 assert(state.peer_send_closed&&!outer.sk_err);
 assert(terra_socket_poll(NULL,&original,NULL)==EPOLLIN);
 transport.peer_shutdown=SHUTDOWN_MASK;terra_track_tcp_close(&state,&transport.sk);
 assert(outer.sk_err==ECONNRESET&&state.peer_closed);
 assert(terra_socket_poll(NULL,&original,NULL)&EPOLLERR);
 assert(sock_error(&outer)==-ECONNRESET);
 assert(terra_socket_poll(NULL,&original,NULL)==(EPOLLIN|EPOLLHUP));
 terra_track_tcp_close(&state,&transport.sk);assert(!outer.sk_err);
 assert(terra_socket_poll(NULL,&original,NULL)==(EPOLLIN|EPOLLHUP));
 state.peer_closed=false;transport.sk.sk_shutdown=SEND_SHUTDOWN;
 terra_track_tcp_close(&state,&transport.sk);assert(!outer.sk_err&&state.peer_closed);
 state.peer_send_closed=false;state.peer_closed=false;transport.sk.sk_shutdown=0;
 terra_track_tcp_close(&state,&transport.sk);assert(outer.sk_err==ECONNRESET);
 unsigned int stopped[]={TCP_CLOSE,TCP_CLOSING};
 for(unsigned int i=0;i<ARRAY_SIZE(stopped);i++) {
  state.connecting=true;transport.sk.sk_state=stopped[i];transport.sk.sk_err=0;
  terra_setup_stream(&state.setup_work);
  assert(!state.connecting&&state.connect_error==-ENETDOWN);
 }
 state.connecting=true;state.connect_error=0;transport.sk.sk_state=TCP_SYN_SENT;
 terra_setup_stream(&state.setup_work);assert(state.connecting&&!state.connect_error);
}
static struct sock *receive_outer;
static int carrier_receive(struct socket *socket,struct msghdr *message,size_t length,int flags) {
 (void)message;(void)length;(void)flags;
 assert(!terra_socket_state(receive_outer->sk_socket)->select_mutex.locked);
 socket->sk->sk_peek_off=7;
 assert(!terra_set_peek_off(receive_outer,11));
 return 2;
}
static void peek_mirror_checks(void) {
 struct sock outer={.sk_peek_off=-1},carrier_sock={.sk_peek_off=-1};
 struct proto_ops native={.set_peek_off=sk_set_peek_off,.recvmsg=native_receive};
 struct proto_ops transport={.recvmsg=carrier_receive,.set_peek_off=carrier_set_peek_off};
 struct socket original={.sk=&outer,.type=SOCK_STREAM},stream={.sk=&carrier_sock,.ops=&transport};
 struct terra_tsi_socket state={.sk=&outer,.stream=&stream,.native_ops=&native};
 outer.sk_socket=&original;outer.sk_user_data=&state;receive_outer=&outer;
 assert(!terra_set_peek_off(&outer,3)&&outer.sk_peek_off==3&&carrier_sock.sk_peek_off==-1);
 state.mode=TERRA_SOCKET_EXTERNAL;state.connecting=true;
 assert(!terra_set_peek_off(&outer,5)&&outer.sk_peek_off==5&&carrier_sock.sk_peek_off==-1);
 carrier_sock.sk_state=TCP_ESTABLISHED;state.opened_needed=32;state.opening_length=0;
 u8 opened[32]={0x01,0x01,0,0,24,0,0,0,0,0,0,0,4,0,0xbb,1,203,0,113,1};
 memcpy(state.opened,opened,sizeof(opened));state.opened_length=31;
 carrier_available=1;carrier[0]=0;
 terra_setup_stream(&state.setup_work);
 assert(!state.connecting&&!state.connect_error&&carrier_sock.sk_peek_off==5);
 state.connected=true;peek_locked_carrier=&carrier_sock;
 assert(!terra_set_peek_off(&outer,0)&&!carrier_sock.sk_peek_off&&!outer.sk_peek_off&&!carrier_sock.locked);
 struct msghdr message={0};
 assert(receive_stream_once(&original,&message,2,MSG_PEEK)==2);
 assert(carrier_sock.sk_peek_off==11&&outer.sk_peek_off==11&&!state.select_mutex.locked);
 assert(!terra_set_peek_off(&outer,-1)&&carrier_sock.sk_peek_off==-1&&outer.sk_peek_off==-1);
 state.mode=0;native_result=3;assert(receive_stream_once(&original,&message,3,0)==3);
 assert(carrier_sock.sk_peek_off==-1&&outer.sk_peek_off==-1);
 peek_locked_carrier=NULL;
}
int main(void) {peer_checks();error_checks();opening_checks();udp_resume_checks();udp_checks();udp_control_checks();udp_receive_shutdown_checks();listen_selection_checks();udp_gso_checks();udp_atomic_credit_checks();udp_poll_checks();tcp_close_checks();peek_mirror_checks();return 0;}
'''

RELEASE_CHECK = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/epoll.h>
#define WRITE_ONCE(target,value) ((target)=(value))
#define READ_ONCE(value) (value)
#define rcu_access_pointer(value) (value)
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_FASYNC 1
#define TCP_CLOSE 0
#define TCP_ESTABLISHED 1
#define RCV_SHUTDOWN 1
#define SEND_SHUTDOWN 2
#define TERRA_HEADER_BYTES 8
#define TERRA_SOCKET_EXTERNAL 2
#define smp_load_acquire(value) (*(value))
struct socket;
struct proto_ops {int (*release)(struct socket *);};
struct socket_wq {int wait;};
struct vsock_sock {long long available;int peer_shutdown;};
struct sock {
 void *sk_user_data;int sk_callback_lock,sk_state,sk_type,sk_err,sk_shutdown;struct socket_wq *sk_wq;
 unsigned int flags;struct vsock_sock vsock;
 void (*sk_data_ready)(struct sock *),(*sk_write_space)(struct sock *);
 void (*sk_state_change)(struct sock *),(*sk_error_report)(struct sock *);
};
struct socket {struct sock *sk;const struct proto_ops *ops;int type;};
struct work_struct {int queued;};
struct delayed_work {struct work_struct work;};
struct terra_tsi_socket {
 struct socket *stream;struct sock *sk;const struct proto_ops *native_ops;
 bool closing,connecting,udp_open;int mode;struct delayed_work timeout_work;struct work_struct setup_work,udp_work;
 int datagrams,wait;void *udp_frame,*udp_receive;
 void (*data_ready)(struct sock *),(*write_space)(struct sock *);
 void (*state_change)(struct sock *),(*error_report)(struct sock *);
};
static struct terra_tsi_socket *current;
static bool callback_inflight;
static struct sock *orphan_on_unlock,*callback_socket;
static int carrier_wakes,outer_wakes,state_wakes,async_write_wakes;
static unsigned int state_wake_key;
static void read_lock_bh(int *lock) {assert(!*lock);*lock=1;}
static void read_unlock_bh(int *lock) {
 assert(*lock);*lock=0;
 if(orphan_on_unlock) {orphan_on_unlock->sk_wq=NULL;orphan_on_unlock=NULL;}
}
static int *sk_sleep(struct sock *socket) {return socket->sk_wq?&socket->sk_wq->wait:NULL;}
static void wake_up_interruptible_all(int *wait) {
 assert(wait&&*wait==123&&callback_socket->sk_callback_lock);carrier_wakes++;
}
static void wake_up_interruptible_poll(int *wait,unsigned int key) {
 assert(wait==&current->wait&&callback_socket->sk_callback_lock);
 assert(key==(EPOLLOUT|EPOLLWRNORM));state_wakes++;state_wake_key=key;
}
static bool sock_flag(struct sock *socket,unsigned int flag) {return socket->flags&flag;}
static void native_write_space(struct sock *socket) {
 assert(socket==current->sk&&sock_flag(socket,SOCK_FASYNC)&&callback_socket->sk_callback_lock);
 async_write_wakes++;outer_wakes++;
}
static struct vsock_sock *vsock_sk(struct sock *socket) {return &socket->vsock;}
static long long vsock_stream_has_data(struct vsock_sock *socket) {return socket->available;}
static void *system_unbound_wq;
static void queue_work(void *queue,struct work_struct *work) {(void)queue;work->queued++;}
static void terra_track_tcp_close(struct terra_tsi_socket *state,struct sock *socket) {(void)state;(void)socket;}
static void terra_socket_wake(struct terra_tsi_socket *state) {assert(state&&!state->closing);outer_wakes++;}
static void write_lock_bh(int *lock) {
 assert(!*lock);*lock=1;
 if(callback_inflight) {callback_inflight=false;current->udp_work.queued=1;}
}
static void write_unlock_bh(int *lock) {assert(*lock);*lock=0;}
static void cancel_work_sync(struct work_struct *work) {work->queued=0;}
static void cancel_delayed_work_sync(struct delayed_work *work) {cancel_work_sync(&work->work);}
static struct terra_tsi_socket *terra_socket_state(struct socket *socket) {return socket->sk->sk_user_data;}
static void lock_sock(struct sock *socket) {(void)socket;}
static void release_sock(struct sock *socket) {(void)socket;}
static void skb_queue_purge(int *queue) {(void)queue;}
#define kfree free
#define rcu_assign_sk_user_data(socket,value) ((socket)->sk_user_data=(value))
static void sock_release(struct socket *stream) {
 assert(!callback_inflight&&!current->udp_work.queued&&!current->setup_work.queued);
 assert(!stream->sk->sk_user_data);free(stream->sk);free(stream);
}
static int native_release(struct socket *socket) {
 assert(socket->sk->sk_state==TCP_CLOSE&&!socket->sk->sk_user_data);
 free(socket->sk);socket->sk=NULL;return 0;
}
'''

RELEASE_MAIN = r'''
int main(void) {
 struct proto_ops native={.release=native_release};
 struct socket socket={.sk=calloc(1,sizeof(struct sock)),.type=SOCK_STREAM};
 current=calloc(1,sizeof(*current));socket.sk->sk_user_data=current;
 current->sk=socket.sk;current->native_ops=&native;current->mode=TERRA_SOCKET_EXTERNAL;
 current->sk->sk_write_space=native_write_space;
 current->stream=calloc(1,sizeof(struct socket));current->stream->sk=calloc(1,sizeof(struct sock));
 current->stream->sk->sk_user_data=current;
 /* Queued skb completion can retain the callback after restore/orphan; the waitqueue needs the callback lock. */
 struct socket_wq wait={.wait=123};callback_socket=current->stream->sk;callback_socket->sk_wq=&wait;
 terra_stream_callback(callback_socket);assert(carrier_wakes==1&&outer_wakes==1);
 current->sk->sk_type=SOCK_DGRAM;current->udp_open=true;callback_socket->sk_state=TCP_ESTABLISHED;
 for(int bytes=0;bytes<TERRA_HEADER_BYTES;bytes++) {
  current->udp_work.queued=0;callback_socket->vsock.available=bytes;
  terra_stream_callback(callback_socket);assert(!current->udp_work.queued);
 }
 current->udp_work.queued=0;callback_socket->vsock.available=TERRA_HEADER_BYTES;
 terra_stream_callback(callback_socket);assert(current->udp_work.queued==1);
 callback_socket->vsock.available=0;current->udp_work.queued=0;callback_socket->sk_err=1;
 terra_stream_callback(callback_socket);assert(current->udp_work.queued==1);
 callback_socket->sk_err=0;current->udp_work.queued=0;callback_socket->sk_state=TCP_CLOSE;
 terra_stream_callback(callback_socket);assert(current->udp_work.queued==1);
 callback_socket->sk_state=TCP_ESTABLISHED;current->udp_work.queued=0;callback_socket->sk_shutdown=RCV_SHUTDOWN;
 terra_stream_callback(callback_socket);assert(current->udp_work.queued==1);
 callback_socket->sk_shutdown=0;current->udp_work.queued=0;callback_socket->vsock.peer_shutdown=SEND_SHUTDOWN;
 terra_stream_callback(callback_socket);assert(current->udp_work.queued==1);
 assert(outer_wakes==1&&state_wakes==TERRA_HEADER_BYTES+5&&state_wake_key==(EPOLLOUT|EPOLLWRNORM));
 current->sk->flags=SOCK_FASYNC;callback_socket->vsock.peer_shutdown=0;current->udp_work.queued=0;
 terra_stream_callback(callback_socket);
 assert(async_write_wakes==1&&outer_wakes==2&&state_wakes==TERRA_HEADER_BYTES+6&&!current->udp_work.queued);
 current->sk->flags=0;
 current->sk->sk_type=SOCK_STREAM;callback_socket->vsock.peer_shutdown=0;current->udp_work.queued=0;
 current->connecting=true;terra_stream_callback(callback_socket);
 assert(current->setup_work.queued==1&&outer_wakes==3);current->setup_work.queued=0;current->connecting=false;
 carrier_wakes=1;outer_wakes=1;
 current->closing=true;terra_stream_callback(callback_socket);assert(carrier_wakes==2&&outer_wakes==1);
 assert(state_wakes==TERRA_HEADER_BYTES+6);
 callback_socket->sk_user_data=NULL;callback_socket->sk_wq=NULL;
 terra_stream_callback(callback_socket);assert(carrier_wakes==2&&outer_wakes==1);
 callback_socket->sk_wq=&wait;orphan_on_unlock=callback_socket;
 terra_stream_callback(callback_socket);assert(carrier_wakes==3&&!callback_socket->sk_wq);
 callback_socket->sk_user_data=current;
 callback_inflight=true;
 assert(!terra_release_socket(&socket)&&!socket.sk&&!callback_inflight);
 return 0;
}
'''


CREDIT_CHECK = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
typedef uint16_t u16;
typedef uint32_t u32;
typedef int64_t s64;
#define SOCK_STREAM 1
#define SOCK_SEQPACKET 5
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSING 11
#define VIRTIO_VSOCK_OP_RST 3
#define VIRTIO_VSOCK_OP_SHUTDOWN 4
#define VIRTIO_VSOCK_OP_RW 5
#define VIRTIO_VSOCK_OP_CREDIT_UPDATE 6
#define VIRTIO_VSOCK_OP_CREDIT_REQUEST 7
#define VIRTIO_VSOCK_SHUTDOWN_SEND 2
#define MSG_PEEK 2
#define MSG_TRUNC 4
#define SEND_SHUTDOWN 2
#define RCV_SHUTDOWN 1
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target,value) ((target)=(value))
#define TASK_INTERRUPTIBLE 1
#define EXPORT_SYMBOL_GPL(symbol)
#define WARN_ONCE(condition,message) (condition)
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define min_t(type,a,b) ((type)(a)<(type)(b)?(type)(a):(type)(b))
#define max_t(type,a,b) ((type)(a)>(type)(b)?(type)(a):(type)(b))
#define le16_to_cpu(value) (value)
#define le32_to_cpu(value) (value)
#define cpu_to_le32(value) (value)
struct test_lock {int id;bool held;};
struct sk_buff;
struct sk_buff_head {struct sk_buff *first,*last;};
struct virtio_vsock_sock {
 struct test_lock tx_lock,rx_lock;
 u32 tx_cnt,peer_fwd_cnt,peer_buf_alloc,fwd_cnt,last_fwd_cnt,rx_bytes,buf_alloc,buf_used;
 struct sk_buff_head rx_queue;
};
struct sock {int sk_state,sk_type,sk_rcvlowat,sk_err,sk_peek_off;unsigned int sk_shutdown;};
struct vsock_sock;
struct vsock_transport_recv_notify_data {int unused;};
struct vsock_transport {
 int (*notify_recv_pre_block)(struct vsock_sock *,size_t,struct vsock_transport_recv_notify_data *);
};
struct vsock_sock {struct sock sk;struct virtio_vsock_sock *trans;const struct vsock_transport *transport;unsigned int peer_shutdown;};
struct virtio_vsock_hdr {u32 buf_alloc,fwd_cnt,flags,len;u16 op;};
struct sk_buff {struct virtio_vsock_hdr header;struct sk_buff *next;u32 len;char bytes[64];struct {u32 offset;} cb;};
struct msghdr {struct iov_iter {char *bytes;size_t copied;} msg_iter;};
struct wait_queue_entry {int unused;};
#define VIRTIO_VSOCK_SKB_CB(skb) (&(skb)->cb)
#define skb_queue_walk(queue,skb) for((skb)=(queue)->first;(skb);(skb)=(skb)->next)
static bool skb_queue_empty(struct sk_buff_head *queue) {return !queue->first;}
static struct sk_buff *skb_peek(struct sk_buff_head *queue) {return queue->first;}
static void __skb_unlink(struct sk_buff *skb,struct sk_buff_head *queue) {
 assert(queue->first==skb);queue->first=skb->next;if(!queue->first)queue->last=NULL;
}
static int copies,copy_failure,dequeued_skbs;
static void consume_skb(struct sk_buff *skb) {(void)skb;dequeued_skbs++;}
static int held_lock,updates,lock_order;
static bool socket_locked=true;
static void spin_lock_bh(struct test_lock *lock) {
 assert(socket_locked&&!held_lock&&!lock->held);
 held_lock=lock->id;lock->held=true;lock_order=(lock_order%10000000)*10+lock->id;
}
static void spin_unlock_bh(struct test_lock *lock) {
 assert(held_lock==lock->id&&lock->held);held_lock=0;lock->held=false;
}
static struct sock *sk_vsock(struct vsock_sock *vsk) {return &vsk->sk;}
static struct vsock_sock *vsock_sk(struct sock *sk) {return (struct vsock_sock *)sk;}
static int sk_peek_offset(struct sock *sk,int flags) {return flags&MSG_PEEK?sk->sk_peek_off:0;}
static void sk_peek_offset_bwd(struct sock *sk,int bytes) {
 int offset=sk->sk_peek_off;if(offset>=0)sk->sk_peek_off=max(offset-bytes,0);
}
static void sk_peek_offset_fwd(struct sock *sk,int bytes) {sk_peek_offset_bwd(sk,-bytes);}
static int sk_set_peek_off(struct sock *sk,int offset) {assert(socket_locked);sk->sk_peek_off=offset;return 0;}
static int skb_copy_datagram_iter(struct sk_buff *skb,size_t offset,struct iov_iter *iter,size_t bytes) {
 assert(socket_locked&&!held_lock&&offset+bytes<=skb->len);
 copies++;if(copies==copy_failure||!iter->bytes)return -EFAULT;
 memcpy(iter->bytes+iter->copied,skb->bytes+offset,bytes);iter->copied+=bytes;return 0;
}
static struct virtio_vsock_hdr *virtio_vsock_hdr(struct sk_buff *skb) {return &skb->header;}
static int sock_rcvlowat(struct sock *sk,int waitall,int length) {
 (void)waitall;return min(sk->sk_rcvlowat?sk->sk_rcvlowat:1,length);
}
static bool virtio_transport_has_space(struct virtio_vsock_sock *vvs) {
 assert(held_lock==vvs->tx_lock.id);
 return min(vvs->buf_alloc,vvs->peer_buf_alloc)>vvs->tx_cnt-vvs->peer_fwd_cnt;
}
void virtio_transport_inc_tx_pkt(struct virtio_vsock_sock *vvs,struct sk_buff *skb);
static int virtio_transport_send_credit_update(struct vsock_sock *vsk) {
 assert(socket_locked&&!held_lock&&!vsk->trans->tx_lock.held&&!vsk->trans->rx_lock.held);
 struct sk_buff packet={0};updates++;virtio_transport_inc_tx_pkt(vsk->trans,&packet);
 assert(packet.header.fwd_cnt==vsk->trans->fwd_cnt&&packet.header.buf_alloc==vsk->trans->buf_alloc);
 return 0;
}
static void initialize(struct vsock_sock *vsk,struct virtio_vsock_sock *vvs,u32 local,u32 peer) {
 memset(vsk,0,sizeof(*vsk));memset(vvs,0,sizeof(*vvs));
 vsk->sk=(struct sock){.sk_state=TCP_ESTABLISHED,.sk_type=SOCK_STREAM,.sk_rcvlowat=1};
 vsk->trans=vvs;vvs->buf_alloc=local;vvs->peer_buf_alloc=peer;
 vvs->tx_lock.id=1;vvs->rx_lock.id=2;held_lock=0;updates=0;lock_order=0;
 copies=0;copy_failure=0;dequeued_skbs=0;vsk->sk.sk_peek_off=-1;
}
static int pre_blocks,sleeps,wait_action,forced_data_error;
static int notify_before_block(struct vsock_sock *vsk,size_t target,struct vsock_transport_recv_notify_data *data) {
 assert(socket_locked&&!held_lock);(void)vsk;(void)target;(void)data;pre_blocks++;return 0;
}
static const struct vsock_transport stream_transport={.notify_recv_pre_block=notify_before_block};
static struct vsock_sock *waiting_vsk;
static s64 vsock_connectible_has_data(struct vsock_sock *vsk) {return forced_data_error?forced_data_error:vsk->trans->rx_bytes;}
static void *sk_sleep(struct sock *sk) {(void)sk;return NULL;}
static void prepare_to_wait(void *queue,struct wait_queue_entry *wait,int state) {
 (void)queue;(void)wait;(void)state;assert(socket_locked);
}
static void finish_wait(void *queue,struct wait_queue_entry *wait) {(void)queue;(void)wait;assert(socket_locked);}
static void release_sock(struct sock *sk) {(void)sk;assert(socket_locked);socket_locked=false;}
static void lock_sock(struct sock *sk) {(void)sk;assert(!socket_locked);socket_locked=true;}
static int signal_pending(void *task) {(void)task;return wait_action==3;}
static void *current;
static int sock_intr_errno(long timeout) {(void)timeout;return -EINTR;}
static long schedule_timeout(long timeout) {
 assert(!socket_locked&&!held_lock&&timeout>0);sleeps++;
 if(wait_action==1) {
  struct sk_buff *skb=waiting_vsk->trans->rx_queue.last;
  assert(skb);skb->bytes[skb->len++]='Z';skb->header.len++;
  waiting_vsk->trans->rx_bytes++;waiting_vsk->trans->buf_used++;
  wait_action=0;return timeout-1;
 }
 if(wait_action==2) {waiting_vsk->peer_shutdown=SEND_SHUTDOWN;return timeout-1;}
 return wait_action==3?timeout-1:0;
}
'''


CREDIT_RECEIVE_CHECKS = r'''
static void queue_receive(struct vsock_sock *vsk,struct virtio_vsock_sock *vvs,struct sk_buff *first,struct sk_buff *second) {
 initialize(vsk,vvs,16,16);vsk->transport=&stream_transport;
 memset(first,0,sizeof(*first));memset(second,0,sizeof(*second));
 first->len=first->header.len=3;memcpy(first->bytes,"abc",3);first->next=second;
 second->len=second->header.len=5;memcpy(second->bytes,"defgh",5);
 vvs->rx_queue=(struct sk_buff_head){.first=first,.last=second};
 vvs->rx_bytes=vvs->buf_used=8;
 waiting_vsk=vsk;pre_blocks=sleeps=wait_action=forced_data_error=0;
}
static void stream_receive_checks(void) {
 struct vsock_sock vsk;struct virtio_vsock_sock vvs;struct sk_buff first,second;
 char bytes[32]={0};struct msghdr message={.msg_iter.bytes=bytes};
 queue_receive(&vsk,&vvs,&first,&second);
 socket_locked=false;
 assert(!vsock_set_peek_off(&vsk.sk,0)&&!socket_locked&&!vsk.sk.sk_peek_off);
 lock_sock(&vsk.sk);vsk.sk.sk_peek_off=-1;
 assert(virtio_transport_stream_dequeue(&vsk,&message,3,MSG_PEEK)==3);
 assert(!memcmp(bytes,"abc",3)&&vsk.sk.sk_peek_off==-1&&vvs.rx_bytes==8&&!vvs.fwd_cnt&&!dequeued_skbs);
 message.msg_iter.copied=0;assert(virtio_transport_stream_dequeue(&vsk,&message,3,MSG_PEEK)==3);
 assert(!memcmp(bytes,"abc",3)&&vsk.sk.sk_peek_off==-1);
 vsk.sk.sk_peek_off=0;message.msg_iter.copied=0;
 assert(virtio_transport_stream_dequeue(&vsk,&message,3,MSG_PEEK)==3&&vsk.sk.sk_peek_off==3);
 message.msg_iter.copied=0;
 assert(virtio_transport_stream_dequeue(&vsk,&message,3,MSG_PEEK)==3&&vsk.sk.sk_peek_off==6);
 assert(!memcmp(bytes,"def",3)&&!vvs.fwd_cnt&&vvs.rx_bytes==8);
 message.msg_iter.copied=0;
 assert(virtio_transport_stream_dequeue(&vsk,&message,2,0)==2&&vsk.sk.sk_peek_off==4);
 assert(!memcmp(bytes,"ab",2)&&first.cb.offset==2&&vvs.rx_bytes==6&&vvs.buf_used==8&&!vvs.fwd_cnt);
 message.msg_iter.bytes=NULL;int before=copies;
 assert(virtio_transport_stream_dequeue(&vsk,&message,2,MSG_TRUNC)==2&&vsk.sk.sk_peek_off==2);
 assert(copies==before&&vvs.rx_bytes==4&&vvs.buf_used==5&&vvs.fwd_cnt==3&&dequeued_skbs==1&&!updates);
 assert(virtio_transport_stream_dequeue(&vsk,&message,2,MSG_PEEK|MSG_TRUNC)==2&&vsk.sk.sk_peek_off==4);
 assert(copies==before&&vvs.rx_bytes==4&&vvs.fwd_cnt==3&&dequeued_skbs==1);
 assert(virtio_transport_stream_dequeue(&vsk,&message,4,MSG_TRUNC)==4&&!vsk.sk.sk_peek_off);
 assert(copies==before&&!vvs.rx_bytes&&!vvs.buf_used&&vvs.fwd_cnt==8&&updates==1&&dequeued_skbs==2);

 queue_receive(&vsk,&vvs,&first,&second);vsk.sk.sk_peek_off=5;
 message=(struct msghdr){.msg_iter.bytes=bytes};
 assert(virtio_transport_stream_dequeue(&vsk,&message,2,MSG_PEEK)==2&&!memcmp(bytes,"fg",2));
 assert(vsk.sk.sk_peek_off==7&&vvs.rx_bytes==8&&!vvs.fwd_cnt);
 queue_receive(&vsk,&vvs,&first,&second);vsk.sk.sk_peek_off=0;copy_failure=2;
 message=(struct msghdr){.msg_iter.bytes=bytes};
 assert(virtio_transport_stream_dequeue(&vsk,&message,8,MSG_PEEK)==3&&vsk.sk.sk_peek_off==3);
 assert(vvs.rx_bytes==8&&!vvs.fwd_cnt&&!held_lock);
 queue_receive(&vsk,&vvs,&first,&second);vsk.sk.sk_peek_off=7;copy_failure=2;
 message=(struct msghdr){.msg_iter.bytes=bytes};
 assert(virtio_transport_stream_dequeue(&vsk,&message,8,0)==3&&vsk.sk.sk_peek_off==4);
 assert(vvs.rx_bytes==5&&vvs.buf_used==5&&vvs.fwd_cnt==3&&!held_lock);
 queue_receive(&vsk,&vvs,&first,&second);copy_failure=1;message.msg_iter.copied=0;
 assert(virtio_transport_stream_dequeue(&vsk,&message,1,MSG_PEEK)==-EFAULT&&vsk.sk.sk_peek_off==-1);
 assert(vvs.rx_bytes==8&&!vvs.fwd_cnt&&!held_lock);

 struct wait_queue_entry wait={0};struct vsock_transport_recv_notify_data notify={0};
 queue_receive(&vsk,&vvs,&first,&second);vsk.sk.sk_peek_off=8;
 assert(vsock_connectible_wait_data(&vsk.sk,&wait,0,&notify,1,MSG_PEEK)==-EAGAIN);
 assert(!sleeps&&!pre_blocks&&vvs.rx_bytes==8&&vsk.sk.sk_peek_off==8);
 assert(vsock_connectible_wait_data(&vsk.sk,&wait,0,&notify,1,0)==8);
 wait_action=1;
 assert(vsock_connectible_wait_data(&vsk.sk,&wait,5,&notify,1,MSG_PEEK)==1);
 assert(sleeps==1&&pre_blocks==1&&socket_locked&&vsk.sk.sk_peek_off==8);
 message=(struct msghdr){.msg_iter.bytes=bytes};
 assert(virtio_transport_stream_dequeue(&vsk,&message,1,MSG_PEEK)==1&&bytes[0]=='Z'&&vsk.sk.sk_peek_off==9);
 vsk.peer_shutdown=SEND_SHUTDOWN;
 assert(!vsock_connectible_wait_data(&vsk.sk,&wait,0,&notify,1,MSG_PEEK));
 vsk.peer_shutdown=0;vsk.sk.sk_peek_off=INT_MAX;
 assert(vsock_connectible_wait_data(&vsk.sk,&wait,0,&notify,1,MSG_PEEK)==-EAGAIN);
 wait_action=2;assert(!vsock_connectible_wait_data(&vsk.sk,&wait,5,&notify,1,MSG_PEEK));
 vsk.peer_shutdown=0;wait_action=0;
 assert(vsock_connectible_wait_data(&vsk.sk,&wait,5,&notify,1,MSG_PEEK)==-EAGAIN);
 wait_action=3;
 assert(vsock_connectible_wait_data(&vsk.sk,&wait,5,&notify,1,MSG_PEEK)==-EINTR);
 vsk.sk.sk_type=SOCK_SEQPACKET;
 assert(vsock_connectible_wait_data(&vsk.sk,&wait,0,NULL,0,0)==9);
 assert(socket_locked&&!held_lock);
}
'''


CREDIT_MAIN = r'''
int main(void) {
 struct vsock_sock socket;struct virtio_vsock_sock vvs;
 struct sk_buff shrink={.header={.buf_alloc=4096,.op=VIRTIO_VSOCK_OP_CREDIT_UPDATE}};
 initialize(&socket,&vvs,24576,49152);
 vvs.fwd_cnt=1228;check_dequeue_credit(&socket);
 assert(!updates&&vvs.last_fwd_cnt==0&&lock_order==12);
 vvs.fwd_cnt=12287;lock_order=0;check_dequeue_credit(&socket);assert(!updates);
 vvs.fwd_cnt=12288;lock_order=0;check_dequeue_credit(&socket);
 assert(updates==1&&vvs.last_fwd_cnt==12288);
 vvs.fwd_cnt=24576;lock_order=0;check_dequeue_credit(&socket);assert(updates==2);

 initialize(&socket,&vvs,81920,8192);vvs.fwd_cnt=4095;
 check_dequeue_credit(&socket);assert(!updates);
 lock_order=0;vvs.fwd_cnt=4096;check_dequeue_credit(&socket);assert(updates==1);
 initialize(&socket,&vvs,4096,24576);vvs.fwd_cnt=2048;
 check_dequeue_credit(&socket);assert(updates==1);
 initialize(&socket,&vvs,1,1);vvs.fwd_cnt=1;
 check_dequeue_credit(&socket);assert(updates==1);

 initialize(&socket,&vvs,24576,49152);socket.sk.sk_rcvlowat=21504;
 vvs.rx_bytes=20480;vvs.fwd_cnt=4096;check_dequeue_credit(&socket);
 assert(updates==1);
 initialize(&socket,&vvs,24576,49152);vvs.rx_bytes=4096;vvs.buf_used=4096;
 spin_lock_bh(&vvs.rx_lock);virtio_transport_dec_rx_pkt(&vvs,1024,0);spin_unlock_bh(&vvs.rx_lock);
 assert(vvs.rx_bytes==3072&&vvs.buf_used==4096&&!vvs.fwd_cnt);
 check_dequeue_credit(&socket);assert(!updates);
 spin_lock_bh(&vvs.rx_lock);virtio_transport_dec_rx_pkt(&vvs,3072,4096);spin_unlock_bh(&vvs.rx_lock);
 assert(!vvs.rx_bytes&&!vvs.buf_used&&vvs.fwd_cnt==4096);lock_order=0;
 check_dequeue_credit(&socket);assert(!updates);
 struct sk_buff piggyback={0};virtio_transport_inc_tx_pkt(&vvs,&piggyback);
 assert(vvs.last_fwd_cnt==4096&&piggyback.header.fwd_cnt==4096&&piggyback.header.buf_alloc==24576);
 lock_order=0;
 check_dequeue_credit(&socket);assert(!updates);
 initialize(&socket,&vvs,8192,8192);
 vvs.last_fwd_cnt=UINT32_MAX-4095;vvs.fwd_cnt=0;
 check_dequeue_credit(&socket);assert(updates==1);

 initialize(&socket,&vvs,24576,24576);vvs.fwd_cnt=4096;
 check_dequeue_credit(&socket);assert(!updates);
 lock_order=0;virtio_transport_space_update(&socket.sk,&shrink);
 assert(updates==1&&vvs.peer_buf_alloc==4096&&vvs.last_fwd_cnt==4096&&lock_order==122);
 lock_order=0;virtio_transport_space_update(&socket.sk,&shrink);assert(updates==1);
 initialize(&socket,&vvs,24576,24576);
 virtio_transport_space_update(&socket.sk,&shrink);assert(!updates);
 initialize(&socket,&vvs,24576,4096);vvs.fwd_cnt=4096;
 shrink.header.buf_alloc=8192;
 virtio_transport_space_update(&socket.sk,&shrink);assert(!updates);
 shrink.header.buf_alloc=4096;

 const int states[]={TCP_SYN_SENT,TCP_CLOSING};
 for(unsigned int i=0;i<sizeof(states)/sizeof(states[0]);i++) {
  initialize(&socket,&vvs,24576,24576);vvs.fwd_cnt=4096;socket.sk.sk_state=states[i];
  virtio_transport_space_update(&socket.sk,&shrink);assert(!updates);
 }
 initialize(&socket,&vvs,24576,24576);vvs.fwd_cnt=4096;socket.sk.sk_type=SOCK_SEQPACKET;
 virtio_transport_space_update(&socket.sk,&shrink);assert(!updates);
 initialize(&socket,&vvs,24576,24576);socket.trans=NULL;
 assert(virtio_transport_space_update(&socket.sk,&shrink)&&!updates);
 const u16 excluded[]={0,VIRTIO_VSOCK_OP_RST,VIRTIO_VSOCK_OP_CREDIT_REQUEST};
 for(unsigned int i=0;i<sizeof(excluded)/sizeof(excluded[0]);i++) {
  initialize(&socket,&vvs,24576,24576);vvs.fwd_cnt=4096;shrink.header.op=excluded[i];
  virtio_transport_space_update(&socket.sk,&shrink);assert(!updates);
 }
 initialize(&socket,&vvs,24576,24576);vvs.fwd_cnt=4096;
 shrink.header.op=VIRTIO_VSOCK_OP_RW;
 virtio_transport_space_update(&socket.sk,&shrink);assert(updates==1);
 initialize(&socket,&vvs,24576,24576);vvs.fwd_cnt=4096;
 shrink.header.op=VIRTIO_VSOCK_OP_SHUTDOWN;shrink.header.flags=VIRTIO_VSOCK_SHUTDOWN_SEND;
 virtio_transport_space_update(&socket.sk,&shrink);assert(!updates);
 initialize(&socket,&vvs,24576,24576);vvs.fwd_cnt=4096;shrink.header.flags=0;
 virtio_transport_space_update(&socket.sk,&shrink);assert(updates==1);
 assert(!held_lock);
 stream_receive_checks();
 return 0;
}
'''


def transport_credit_checks(source: str) -> str:
    dequeue = declaration(source, r'^static ssize_t\nvirtio_transport_stream_do_dequeue\(')
    snapshot_begin = dequeue.index('\tspin_lock_bh(&vvs->tx_lock);')
    snapshot_end = dequeue.index('\tspin_lock_bh(&vvs->rx_lock);', snapshot_begin)
    notification_begin = dequeue.index('\tfwd_cnt_delta =')
    notification_end = dequeue.index('\n\treturn total;', notification_begin)
    return (
        declaration(source, r'^static void virtio_transport_dec_rx_pkt\(') + '\n'
        + declaration(source, r'^void virtio_transport_inc_tx_pkt\(') + '\n'
        + 'static void check_dequeue_credit(struct vsock_sock *vsk) {\n'
        + 'struct virtio_vsock_sock *vvs=vsk->trans;u32 fwd_cnt_delta,receive_window,peer_receive_window;\n'
        + 'bool low_rx_bytes;int receive_low_water;\n'
        + dequeue[snapshot_begin:snapshot_end]
        + '\tspin_lock_bh(&vvs->rx_lock);\n'
        + dequeue[notification_begin:notification_end] + '\n}\n'
        + declaration(source, r'^static bool virtio_transport_space_update\(')
    )


def transport_receive_checks(source: str, connection: str) -> str:
    return ('\n'.join(declaration(source, rf'^(?:static )?ssize_t\n{name}\(') for name in (
        'virtio_transport_stream_do_peek', 'virtio_transport_stream_do_dequeue',
        'virtio_transport_stream_dequeue'))
        + '\n' + declaration(connection, r'^static int vsock_connectible_wait_data\(')
        + '\n' + declaration(connection, r'^static int vsock_set_peek_off\('))


def consumption_checks(source: str) -> str:
    receive = declaration(source, r'^static int terra_recvmsg\(')
    wait_condition = re.search(r'wait_event_interruptible_timeout\(\*sk_sleep\(state->sk\),\s*(.*?), timeout\);',
                               receive, re.DOTALL)[1]
    stream_begin = receive.index('\tif (socket->type == SOCK_STREAM) {') + len('\tif (socket->type == SOCK_STREAM) {')
    stream_end = receive.index('\n\t}\n\tif (!smp_load_acquire(&state->udp_open)', stream_begin)
    native_begin = receive.index('\t\tif (state->native_ops->poll')
    native_end = receive.index('\t\tif (flags & MSG_PEEK)', native_begin)
    error_begin = receive.index('\tif (!smp_load_acquire(&state->udp_open)')
    error_end = receive.index('\tif (flags & ~', error_begin)
    external_begin = receive.index('\t\t\tif (datagram', receive.index('datagram = skb_dequeue'))
    external_end = receive.index('\n\t\t}', external_begin)
    configure = declaration(source, r'^static int terra_setsockopt\(')
    configure_begin = configure.index('\tif (!error && socket->type == SOCK_STREAM)')
    configure_end = configure.index('\n\treturn error;', configure_begin)
    connect = declaration(source, r'^static int terra_connect_locked\(')
    connect_begin = connect.index('\tif (peer_length <')
    connect_end = connect.index('\tif (READ_ONCE(state->connecting))', connect_begin)
    return (
        'static bool udp_receive_ready(struct terra_tsi_socket *state,struct socket *socket) {\n'
        + 'return ' + wait_condition + ';\n}\n'
        + 'static int connect_native_after_lock(struct socket *socket,struct sockaddr *peer,int peer_length,int flags) {\n'
        + 'struct terra_tsi_socket *state=terra_socket_state(socket);int error;\n'
        + connect[connect_begin:connect_end] + 'error=-EALREADY;goto unlock;\nunlock:mutex_unlock(&state->select_mutex);return error;\n}\n'
        + 'static int receive_stream_once(struct socket *socket,struct msghdr *message,size_t length,int flags) {\n'
        + 'struct terra_tsi_socket *state=terra_socket_state(socket);int error;\n'
        + receive[stream_begin:stream_end] + '\n}\n'
        + 'static int receive_native_once(struct socket *socket,struct msghdr *message,size_t length,int flags) {\n'
        + 'struct terra_tsi_socket *state=terra_socket_state(socket);int error=-EAGAIN;\n'
        + receive[native_begin:native_end] + '\nunlock:return error;\n}\n'
        + 'static int receive_error_queue(struct socket *socket,struct msghdr *message,size_t length,int flags) {\n'
        + 'struct terra_tsi_socket *state=terra_socket_state(socket);int error=0;(void)error;\n'
        + receive[error_begin:error_end] + '\nabort();\n}\n'
        + 'static void resume_external_receive(struct terra_tsi_socket *state,bool datagram) {\n'
        + receive[external_begin:external_end] + '\n}\n'
        + 'static int resume_receive_config(struct socket *socket,int error,int level,int option) {\n'
        + 'struct terra_tsi_socket *state=terra_socket_state(socket);\n'
        + configure[configure_begin:configure_end] + '\nreturn error;\n}\n'
    )


def udp_send_validation(source: str) -> str:
    send = declaration(source, r'^static int terra_sendmsg\(')
    begin = send.index('\terror = terra_udp_control(state->sk, message, &segment);')
    end = send.index('\tif (READ_ONCE(state->sk->sk_shutdown)', begin)
    return (
        re.search(r'^#define TERRA_UDP_MAX_SEGMENTS [0-9]+$', source, re.MULTILINE)[0] + '\n'
        + 'static int check_udp_send_validation(struct sock *sk,struct msghdr *message,size_t length) {\n'
        + 'struct terra_tsi_socket socket_state={.sk=sk},*state=&socket_state;u16 segment;int error;\n'
        + send[begin:end] + '\nreturn 0;\n}\n'
    )


TCP_INFO_CHECK = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/udp.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define __user
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_TCP 6
#define SOL_IP 0
#define SOL_IPV6 41
#define SOL_UDP 17
#define MSG_DONTWAIT 1
#define TCP_ESTABLISHED 1
#define TCP_FIN_WAIT2 5
#define TCP_CLOSE 7
#define TCP_CLOSE_WAIT 8
#define TERRA_SOCKET_EXTERNAL 2
#define TERRA_TCP_RECEIVE_BYTES 81920
#define TERRA_TCP_SEND_BYTES 49152
#define RCV_SHUTDOWN 1
#define SEND_SHUTDOWN 2
#define READ_ONCE(value) (value)
#define smp_load_acquire(value) (*(value))
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(type,a,b) ((type)(a)<(type)(b)?(type)(a):(type)(b))
#define max_t(type,a,b) ((type)(a)>(type)(b)?(type)(a):(type)(b))
#define get_user(value,pointer) ((pointer)?((value)=*(pointer),0):-EFAULT)
#define put_user(value,pointer) ((pointer)?(*(pointer)=(value),0):-EFAULT)
static int copy_to_user(void *destination,const void *source,size_t length) {
 if(!destination)return 1;
 memcpy(destination,source,length);return 0;
}
struct mutex {bool locked;};
static void mutex_lock(struct mutex *mutex) {assert(!mutex->locked);mutex->locked=true;}
static void mutex_unlock(struct mutex *mutex) {assert(mutex->locked);mutex->locked=false;}
struct tcp_sock {u64 bytes_sent,bytes_acked;struct {int user_mss;} rx_opt;};
struct sock {int sk_err;unsigned int sk_shutdown;bool locked;struct tcp_sock tcp;void *sk_user_data;};
struct virtio_vsock_sock {int tx_lock;u32 tx_cnt,peer_fwd_cnt,buf_alloc,peer_buf_alloc;};
struct vsock_sock {struct sock sk;struct virtio_vsock_sock *trans;};
static struct tcp_sock *tcp_sk(struct sock *sk) {return &sk->tcp;}
static struct vsock_sock *vsock_sk(struct sock *sk) {return (struct vsock_sock *)sk;}
struct socket;
struct msghdr {void *msg_name;unsigned int msg_namelen,msg_controllen;int msg_iter;};
struct proto_ops {
 int (*sendmsg)(struct socket *,struct msghdr *,size_t);
 int (*getsockopt)(struct socket *,int,int,char *,int *);
};
struct socket {struct sock *sk;int type;const struct proto_ops *ops;};
struct terra_tsi_socket {
 struct sock *sk;int mode;bool connected,connecting,udp_open;struct socket *stream;
 struct mutex select_mutex;const struct proto_ops *native_ops;
};
static struct sock *outer;
static void lock_sock(struct sock *sk) {assert(sk==outer&&!sk->locked);sk->locked=true;}
static void release_sock(struct sock *sk) {assert(sk==outer&&sk->locked);sk->locked=false;}
static void spin_lock_bh(int *lock) {assert(outer->locked&&!*lock);*lock=1;}
static void spin_unlock_bh(int *lock) {assert(outer->locked&&*lock);*lock=0;}
static struct terra_tsi_socket *terra_socket_state(struct socket *socket) {return socket->sk->sk_user_data;}
static int sock_error(struct sock *sk) {int error=sk->sk_err;sk->sk_err=0;return -error;}
static int send_result,native_calls;
static bool reserved_before_return;
static int carrier_send(struct socket *socket,struct msghdr *message,size_t length) {
 assert(!outer->locked&&!message->msg_name&&!message->msg_namelen);(void)length;
 if(send_result>0&&!reserved_before_return)vsock_sk(socket->sk)->trans->tx_cnt+=send_result;
 message->msg_iter+=send_result>0?send_result:0;return send_result;
}
static int native_send(struct socket *socket,struct msghdr *message,size_t length) {
 (void)socket;(void)message;(void)length;native_calls++;return send_result;
}
static int native_info(struct socket *socket,int level,int option,char *value,int *length) {
 (void)socket;(void)level;(void)option;(void)value;(void)length;native_calls++;return 17;
}
'''

TCP_INFO_MAIN = r'''
int main(void) {
 struct virtio_vsock_sock transport={.buf_alloc=81920,.peer_buf_alloc=49152};
 struct vsock_sock carrier={.trans=&transport};struct sock sk={0};outer=&sk;
 struct proto_ops operations={.sendmsg=carrier_send};
 struct proto_ops native={.sendmsg=native_send,.getsockopt=native_info};
 struct socket stream={.sk=&carrier.sk,.type=SOCK_STREAM,.ops=&operations};
 struct terra_tsi_socket state={.sk=&sk,.mode=TERRA_SOCKET_EXTERNAL,.connected=true,.stream=&stream,.native_ops=&native};
 struct socket socket={.sk=&sk,.type=SOCK_STREAM};sk.sk_user_data=&state;
 struct tcp_info information;int length=sizeof(information);
 assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(length==(int)sizeof(information)&&information.tcpi_snd_wnd==49152&&information.tcpi_bytes_acked==1);
 assert(information.tcpi_snd_mss==UINT16_MAX&&information.tcpi_rcv_mss==UINT16_MAX&&information.tcpi_advmss==UINT16_MAX);
 sk.tcp.rx_opt.user_mss=1200;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_snd_mss==1200&&information.tcpi_advmss==1200&&information.tcpi_rcv_mss==UINT16_MAX);
 sk.tcp.rx_opt.user_mss=0;
 transport.tx_cnt=32;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==1&&information.tcpi_snd_wnd==49120);
 transport.tx_cnt=transport.peer_fwd_cnt=0;
 struct msghdr message={.msg_name=&sk,.msg_namelen=8};send_result=100;
 assert(check_tcp_send(&socket,&message,500)==100&&sk.tcp.bytes_sent==100&&message.msg_iter==100);
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==1&&information.tcpi_snd_wnd==49052);
 transport.peer_fwd_cnt=40;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==41&&information.tcpi_snd_wnd==49092);
 transport.peer_buf_alloc=32;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(!information.tcpi_snd_wnd&&information.tcpi_bytes_acked==41&&information.tcpi_snd_mss==UINT16_MAX);
 transport.peer_buf_alloc=UINT32_MAX;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_snd_wnd==TERRA_TCP_SEND_BYTES);

 /* A new carrier reservation precedes its syscall's successful byte bookkeeping. */
 transport.peer_buf_alloc=49152;transport.tx_cnt+=100;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==41&&sk.tcp.bytes_sent==100);
 reserved_before_return=true;
 assert(check_tcp_send(&socket,&message,100)==100&&sk.tcp.bytes_sent==200);
 reserved_before_return=false;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==41);
 transport.peer_fwd_cnt=transport.tx_cnt;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==201);
 const int failed[]={-EAGAIN,-EPIPE,0};
 for(unsigned int i=0;i<sizeof(failed)/sizeof(failed[0]);i++) {
  send_result=failed[i];assert(check_tcp_send(&socket,&message,100)==failed[i]&&sk.tcp.bytes_sent==200);
 }

 sk.tcp.bytes_sent=(UINT64_C(1)<<32)+123;
 transport.tx_cnt=22;transport.peer_fwd_cnt=UINT32_MAX-27;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==(UINT64_C(1)<<32)+74);
 transport.peer_fwd_cnt=transport.tx_cnt;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==sk.tcp.bytes_sent+1);
 transport.tx_cnt+=100;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(information.tcpi_bytes_acked==sk.tcp.bytes_sent+1);

 state.connected=false;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(!information.tcpi_snd_wnd&&!information.tcpi_bytes_acked);
 state.connected=true;carrier.trans=NULL;
 length=sizeof(information);assert(!terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length));
 assert(!information.tcpi_snd_wnd&&!information.tcpi_bytes_acked);carrier.trans=&transport;
 length=-1;assert(terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length)==-EINVAL);
 length=sizeof(information);assert(terra_getsockopt(&socket,SOL_TCP,TCP_INFO,NULL,&length)==-EFAULT);
 state.mode=0;send_result=7;
 assert(check_tcp_send(&socket,&message,7)==7&&native_calls==1&&sk.tcp.bytes_sent==(UINT64_C(1)<<32)+123);
 length=sizeof(information);assert(terra_getsockopt(&socket,SOL_TCP,TCP_INFO,(char *)&information,&length)==17&&native_calls==2);
 socket.type=SOCK_DGRAM;state.connected=false;
 const int unsupported_udp_options[][2]={{SOL_IP,IP_MTU},{SOL_IPV6,IPV6_MTU}};
 for(unsigned int i=0;i<sizeof(unsupported_udp_options)/sizeof(unsupported_udp_options[0]);i++) {
  int level=unsupported_udp_options[i][0],option=unsupported_udp_options[i][1];
  state.udp_open=false;int before_native_calls=native_calls;
  assert(terra_getsockopt(&socket,level,option,(char *)&information,&length)==17);
  assert(native_calls==before_native_calls+1);
  state.udp_open=true;before_native_calls=native_calls;
  assert(terra_getsockopt(&socket,level,option,(char *)&information,&length)==-ENOPROTOOPT);
  assert(native_calls==before_native_calls&&state.mode==0);
 }
 const int supported_udp_options[][2]={{SOL_IP,IP_MTU_DISCOVER},{SOL_IP,IP_RECVTOS},
  {SOL_IPV6,IPV6_DONTFRAG},{SOL_UDP,UDP_SEGMENT},{SOL_UDP,UDP_GRO}};
 for(unsigned int i=0;i<sizeof(supported_udp_options)/sizeof(supported_udp_options[0]);i++) {
  int before_native_calls=native_calls;
  assert(terra_getsockopt(&socket,supported_udp_options[i][0],supported_udp_options[i][1],(char *)&information,&length)==17);
  assert(native_calls==before_native_calls+1);
 }
 assert(!sk.locked&&!state.select_mutex.locked&&!transport.tx_lock);
 return 0;
}
'''


def tcp_info_checks(source: str) -> str:
    send = declaration(source, r'^static int terra_sendmsg\(')
    begin = send.index('\tif (socket->type == SOCK_STREAM) {')
    end = send.index('\n\tif (state->stream', begin)
    return (
        re.search(r'^#define TERRA_TCP_SEGMENT_BYTES [0-9]+$', source, re.MULTILINE)[0] + '\n'
        + declaration(source, r'^static bool terra_udp_option\(') + '\n'
        + declaration(source, r'^static int terra_getsockopt\(') + '\n'
        + 'static int check_tcp_send(struct socket *socket,struct msghdr *message,size_t length) {\n'
        + 'struct terra_tsi_socket *state=terra_socket_state(socket);int error;\n'
        + send[begin:end] + '\nabort();\n}\n'
    )


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-directory', type=Path, help='check wrapper socket.c before patch export')
    args = parser.parse_args()
    source = (args.source_directory / 'socket.c').read_text() if args.source_directory \
        else read_overlay_source('net/terra/socket.c')
    if 'terra_network_' in source or 'TERRA_HELPER' in source:
        raise ValueError('The kernel socket wrapper must not carry the removed shared dispatcher or helper relay.')
    transport = patched_source('net/vmw_vsock/virtio_transport_common.c')
    request_credit = declaration(transport, r'^int virtio_transport_send_credit_request\(')
    functions = request_credit + '\n' + '\n'.join(declaration(source, rf'^static [^\n]*\b{name}\(') for name in (
        'terra_decode_error', 'terra_encode_peer', 'terra_decode_peer', 'terra_canonical_peer',
        'terra_peer_equal', 'terra_validate_opened', 'terra_open_timeout', 'terra_frame_header',
        'terra_resume_udp', 'terra_receive_udp_frame', 'terra_udp_writable', 'terra_udp_control', 'terra_send_udp',
        'terra_track_tcp_close', 'terra_setup_stream', 'terra_socket_poll', 'terra_set_peek_off', 'terra_listen'))
    with tempfile.TemporaryDirectory(prefix='terra-kernel-vsock-') as temporary:
        directory = Path(temporary)
        program = directory / 'adapter.c'
        executable = directory / 'adapter'
        program.write_text(PRELUDE + functions + consumption_checks(source) + udp_send_validation(source) + CHECKS)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-sign-compare',
                        '-fsanitize=address,undefined', '-g', str(program), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
        program.write_text(TCP_INFO_CHECK + tcp_info_checks(source) + TCP_INFO_MAIN)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare',
                        '-fsanitize=address,undefined', '-g', str(program), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
        connection = patched_source('net/vmw_vsock/af_vsock.c')
        program.write_text(CREDIT_CHECK + transport_credit_checks(transport)
                           + transport_receive_checks(transport, connection)
                           + CREDIT_RECEIVE_CHECKS + CREDIT_MAIN)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare',
                        '-fsanitize=address,undefined', '-g', str(program), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
        release_functions = '\n'.join(declaration(source, rf'^static [^\n]*\b{name}\([^;\n]*\)\n') for name in (
            'terra_resume_udp', 'terra_stream_callback', 'terra_restore_stream_callbacks', 'terra_detach_stream', 'terra_release_socket'))
        program.write_text(RELEASE_CHECK + release_functions + RELEASE_MAIN)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-g', str(program), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
    print('kernel opening, TCP peek/discard/TCP_INFO, UDP controls/GSO/atomic backpressure, transport credit, and callback teardown checks passed')


if __name__ == '__main__':
    main()
