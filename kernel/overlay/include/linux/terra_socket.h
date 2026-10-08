/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_TERRA_SOCKET_H
#define _LINUX_TERRA_SOCKET_H
#define TERRA_SOCKET_VERSION 1
struct socket;
struct sockaddr;
int terra_tsi_attach(struct socket *socket);
int terra_tsi_select_native(struct socket *socket, struct sockaddr *peer,
			    int peer_length);
#endif
