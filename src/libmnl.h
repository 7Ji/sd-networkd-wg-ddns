// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2008-2012 Pablo Neira Ayuso <pablo@netfilter.org>.
 */

/* Modified from source of wireguard tools
	commit 13f4ac4cb74b5a833fa7f825ba785b1e5774e84f
	path 'src/netlink.h' */
/* This is a minimized version of libmnl meant to be #include'd */
#ifndef _LIBMNL_H
#define _LIBMNL_H
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#define MNL_CB_ERROR	-1
#define MNL_CB_STOP	0
#define MNL_CB_OK	1

enum mnl_attr_data_type {
	MNL_TYPE_UNSPEC,
	MNL_TYPE_U8,
	MNL_TYPE_U16,
	MNL_TYPE_U32,
	MNL_TYPE_U64,
	MNL_TYPE_STRING,
	MNL_TYPE_FLAG,
	MNL_TYPE_MSECS,
	MNL_TYPE_NESTED,
	MNL_TYPE_NESTED_COMPAT,
	MNL_TYPE_NUL_STRING,
	MNL_TYPE_BINARY,
	MNL_TYPE_MAX,
};

typedef int (*mnl_attr_cb_t)(const struct nlattr *attr, void *data);
typedef int (*mnl_cb_t)(const struct nlmsghdr *nlh, void *data);

uint16_t mnl_attr_get_type(struct nlattr const *attr);
uint16_t mnl_attr_get_payload_len(struct nlattr const *attr);
void *mnl_attr_get_payload(struct nlattr const *attr);
int mnl_attr_parse_nested(struct nlattr const *nested, mnl_attr_cb_t cb, void *data);
int mnl_attr_validate(struct nlattr const *attr, enum mnl_attr_data_type type);
uint32_t mnl_attr_get_u32(struct nlattr const *attr);
int mnl_attr_parse(struct nlmsghdr const *nlh, unsigned int offset, mnl_attr_cb_t cb, void *data);
struct mnlg_socket *mnlg_socket_open(char const *family_name, uint8_t version);
struct nlmsghdr *mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd, uint16_t flags);
void mnl_attr_put_strz(struct nlmsghdr *nlh, uint16_t type, char const *data);
int mnlg_socket_send(struct mnlg_socket *nlg, struct nlmsghdr const *nlh);
int mnlg_socket_recv_run(struct mnlg_socket *nlg, mnl_cb_t data_cb, void *data);
void mnlg_socket_close(struct mnlg_socket *nlg);
void mnl_attr_put_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t data);
struct nlattr *mnl_attr_nest_start(struct nlmsghdr *nlh, uint16_t type);
struct nlattr *mnl_attr_nest_start_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type);
bool mnl_attr_put_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, size_t len, const void *data);
void mnl_attr_nest_end(struct nlmsghdr *nlh, struct nlattr *start);
size_t mnl_ideal_socket_buffer_size(void);

#endif