// SPDX-License-Identifier: AGPL-3.0-or-later
/* C */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
/* POSIX */
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
/* Linux */
#include <linux/if.h>
#include <linux/limits.h>
#include <linux/wireguard.h>
/* Network */
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* Library */
#include "libmnl.h"
/* Local */
#include "version.h"

#define print_with_prefix_and_source(prefix, format, arg...) \
    printf("["prefix"] %s:%d: "format, __FUNCTION__, __LINE__, ##arg)
#define print_with_prefix(prefix, format, arg...) \
    printf("["prefix"] "format, ##arg)

#define print_info(format, arg...) print_with_prefix("INFO", format, ##arg)
#define print_warn(format, arg...) print_with_prefix("WARN", format, ##arg)
#define print_error(format, arg...)  \
    print_with_prefix_and_source("ERROR", format, ##arg)
#define print_error_with_errno(format, arg...) \
    print_error(format", errno: %d, error: %s", ##arg, errno, strerror(errno))

#define println_info(format, arg...) print_info(format"\n", ##arg)
#define println_warn(format, arg...) print_warn(format"\n", ##arg)
#define println_error(format, arg...)  print_error(format"\n", ##arg)
#define println_error_with_errno(format, arg...) \
    print_error(format", errno: %d, error: %s\n", ##arg, errno, strerror(errno))

#define println(format, arg...) printf(format"\n", ##arg)

#define dump_netdev(netdev)
#define min2(A, B) (A > B ? B : A)

#define ALLOC_BASE 0x10
#define SIZE_BUFFER 0x100000
#define PATH_CONFIGS "/etc/systemd/network"
#define NETDEV_STEM_MAX NAME_MAX - 6 // including terminating '\0', NAME_MAX + 1 - 7
#define TITLE_NETDEV "NetDev"
#define TITLE_PEER "WireGuardPeer"
#define KEY_NAME "Name"
#define KEY_KIND "Kind"
#define KEY_PUBLICKEY "PublicKey"
#define KEY_ENDPOINT "Endpoint"
#define VALUE_WIREGUARD "wireguard"
#define LEN_KEY_KIND (sizeof KEY_KIND) - 1
#define LEN_KEY_NAME (sizeof KEY_NAME) - 1
#define LEN_VALUE_WIREGUARD (sizeof VALUE_WIREGUARD) -1
#define LEN_KEY_PUBLICKEY (sizeof KEY_PUBLICKEY) - 1
#define LEN_KEY_ENDPOINT (sizeof KEY_ENDPOINT) - 1
#define LEN_DOMAIN 255
#define LEN_WGKEY_RAW 32
#define LEN_WGKEY_BASE64 ((((LEN_WGKEY_RAW) + 2) / 3) * 4)
#define LEN_IPV4_STRING 15 // 3 * 4 + 3
#define LEN_IPV6_STRING 39 // 4 * 8 + 7
#define SOCKET_BUFFER_SIZE (mnl_ideal_socket_buffer_size())

enum host_type {
    HOST_TYPE_DOMAIN,
    HOST_TYPE_IPV4,
    HOST_TYPE_IPV6
};

char *host_type_strings[] = {
    "domain",
    "IPv4",
    "IPv6"
};

#define SOCKADDR_IN46_DECLARE { \
    struct sockaddr_in6 sockaddr_in6; \
    struct sockaddr_in sockaddr_in; \
}

union sockaddr_in46 SOCKADDR_IN46_DECLARE;

struct endpoint_domain {
    char name[LEN_DOMAIN + 1]; // len = 255 (max length of domain name)
    unsigned short len_name;
    in_port_t port; // Network byte order
};

struct peer {
    uint8_t public_key[LEN_WGKEY_RAW]; // len = 44
    union {
        struct endpoint_domain domain;
        union {
            union sockaddr_in46 sockaddr_in46;
            union SOCKADDR_IN46_DECLARE;
        };
    } endpoint;
    enum host_type endpoint_type;
    struct timespec last_handshake;
};

#define NETDEV_NO_PEERS_DECLARE { \
    char name[IFNAMSIZ]; \
    unsigned short len_name; \
    uint32_t ifindex; \
}

struct netdev_no_peers NETDEV_NO_PEERS_DECLARE;

struct netdev {
    union {
        struct netdev_no_peers netdev_no_peers;
        struct NETDEV_NO_PEERS_DECLARE;
    };
    struct peer *peers;
    unsigned short peers_count;
    unsigned short peers_allocated;
};

enum parse_status {
    parse_status_none,
    parse_status_netdev_section,
    parse_status_peer_section,
    parse_status_other_section
};

static inline
bool in_addr_equal(
    struct in_addr const *const restrict some,
    struct in_addr const *const restrict other
) {
    return some->s_addr == other->s_addr;
}

static inline 
void ipv4_string_from_in(
    char ipv4_string[LEN_IPV4_STRING + 1],
    struct in_addr const *const restrict in_addr
) {
    if (!inet_ntop(AF_INET, in_addr, ipv4_string, LEN_IPV4_STRING + 1)) {
        println_error_with_errno("Failed to format IPv4 string");
        memcpy(ipv4_string, "xxx.xxx.xxx.xxx", LEN_IPV4_STRING + 1);
    }
}

bool sockaddr_in_equal(
    struct sockaddr_in const *const restrict some,
    struct sockaddr_in const *const restrict other
) {
    char ipv4_some[LEN_IPV4_STRING + 1];
    char ipv4_other[LEN_IPV4_STRING + 1];
    bool result;

    result = some->sin_port == other->sin_port &&
        in_addr_equal(&some->sin_addr, &other->sin_addr);
    if (!result) {
        ipv4_string_from_in(ipv4_some, &some->sin_addr);
        ipv4_string_from_in(ipv4_other, &other->sin_addr);
        println_info("IPv4 address %s:%hu != %s:%hu", ipv4_some, ntohs(some->sin_port), ipv4_other, ntohs(other->sin_port));
    }
    return result;
}

static inline
bool in6_addr_equal (
    struct in6_addr const *const restrict some,
    struct in6_addr const *const restrict other
) {
    return some->s6_addr == other->s6_addr;
}

static inline 
void ipv6_string_from_in6(
    char ipv6_string[LEN_IPV6_STRING + 1],
    struct in6_addr const *const restrict in6_addr
) {
    if (!inet_ntop(AF_INET6, in6_addr, ipv6_string, LEN_IPV6_STRING + 1)) {
        println_error_with_errno("Failed to format IPv6 string");
        memcpy(ipv6_string, "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx", LEN_IPV6_STRING + 1);
    }
}

bool sockaddr_in6_equal (
    struct sockaddr_in6 const *const restrict some,
    struct sockaddr_in6 const *const restrict other
) {
    char ipv6_some[LEN_IPV6_STRING + 1];
    char ipv6_other[LEN_IPV6_STRING + 1];
    bool result;

    result = some->sin6_port == other->sin6_port &&
        in6_addr_equal(&some->sin6_addr, &other->sin6_addr);
    if (!result) {
        ipv6_string_from_in6(ipv6_some, &some->sin6_addr);
        ipv6_string_from_in6(ipv6_other, &other->sin6_addr);
        println_info("IPv6 address [%s]:%hu != [%s]:%hu", ipv6_some, ntohs(some->sin6_port), ipv6_other, ntohs(other->sin6_port));
    }
    return result;
}

static inline
bool sockaddr_in46_equal (
    union sockaddr_in46 const *const restrict some,
    union sockaddr_in46 const *const restrict other,
    enum host_type const type
){
    return type == HOST_TYPE_IPV6 ? 
        sockaddr_in6_equal(&some->sockaddr_in6, &other->sockaddr_in6) :
        sockaddr_in_equal(&some->sockaddr_in, &other->sockaddr_in);
}

int init_netdev_peers(struct netdev *const restrict netdev, unsigned short peers_allocated) {
    if (!peers_allocated) peers_allocated = ALLOC_BASE;
    netdev->peers = malloc(sizeof *netdev->peers * peers_allocated);
    if (!netdev->peers) {
        println_error_with_errno("Failed to allocate memory for peers");
        return -1;
    }
    netdev->peers_allocated = peers_allocated;
    netdev->peers_count = 0;
    return 0;
}

void init_peer(struct peer *const restrict peer) {
    peer->public_key[0] = '\0';
    peer->endpoint.domain.name[0] = '\0';
    peer->endpoint.domain.len_name = 0;
    peer->endpoint.domain.port = 0;
    peer->endpoint_type = HOST_TYPE_DOMAIN;
    peer->last_handshake.tv_nsec = 0;
    peer->last_handshake.tv_sec = 0;
}

/* encode_base64, key_to_base64, decode_base64, key_from_base64 are borrowed from wireguard-tools/src/encoding.c */
static inline void encode_base64(char dest[static 4], const uint8_t src[static 3])
{
	uint8_t const input[] = { (src[0] >> 2) & 63, ((src[0] << 4) | (src[1] >> 4)) & 63, ((src[1] << 2) | (src[2] >> 6)) & 63, src[2] & 63 };

	for (unsigned int i = 0; i < 4; ++i)
		dest[i] = input[i] + 'A'
			  + (((25 - input[i]) >> 8) & 6)
			  - (((51 - input[i]) >> 8) & 75)
			  - (((61 - input[i]) >> 8) & 15)
			  + (((62 - input[i]) >> 8) & 3);

}

void key_to_base64(char base64[static LEN_WGKEY_BASE64 + 1], const uint8_t key[static LEN_WGKEY_RAW])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN / 3; ++i)
		encode_base64(&base64[i * 4], &key[i * 3]);
	encode_base64(&base64[i * 4], (const uint8_t[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
	base64[LEN_WGKEY_BASE64 - 1] = '=';
	base64[LEN_WGKEY_BASE64] = '\0';
}

static inline int decode_base64(const char src[static 4])
{
	int val = 0;

	for (unsigned int i = 0; i < 4; ++i)
		val |= (-1
			    + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64))
			    + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70))
			    + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5))
			    + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63)
			    + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)
			) << (18 - 6 * i);
	return val;
}

bool key_from_base64(uint8_t key[static LEN_WGKEY_RAW], const char *base64)
{
	unsigned int i;
	volatile uint8_t ret = 0;
	int val;

	if (base64[LEN_WGKEY_BASE64 - 1] != '=')
		return false;

	for (i = 0; i < WG_KEY_LEN / 3; ++i) {
		val = decode_base64(&base64[i * 4]);
		ret |= (uint32_t)val >> 31;
		key[i * 3 + 0] = (val >> 16) & 0xff;
		key[i * 3 + 1] = (val >> 8) & 0xff;
		key[i * 3 + 2] = val & 0xff;
	}
	val = decode_base64((const char[]){ base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A' });
	ret |= ((uint32_t)val >> 31) | (val & 0xff);
	key[i * 3 + 0] = (val >> 16) & 0xff;
	key[i * 3 + 1] = (val >> 8) & 0xff;

	return 1 & ((ret - 1) >> 8);
}

void peer_endpoint_complete(
    struct peer *const restrict peer,
    char const *const restrict host,
    unsigned short len_host,
    in_port_t port
) {
    bool could_v4;
    char buffer[LEN_DOMAIN + 1];

    port = htons(port); // Convert to network byte order
    len_host = min2(len_host, (sizeof buffer) - 1);
    if (host[0] == '[' && host[len_host] == ']') { // Definitely not v4
        could_v4 = false;
    } else {
        could_v4 = true;
    }
    memcpy(buffer, host + 1, len_host - 2);
    buffer[len_host - 2] = '\0';
    if (inet_pton(AF_INET6, buffer, &peer->endpoint.sockaddr_in6.sin6_addr) == 1) { // Is v6
        peer->endpoint_type = HOST_TYPE_IPV6;
        peer->endpoint.sockaddr_in6.sin6_family = AF_INET6;
        peer->endpoint.sockaddr_in6.sin6_port = port;
        peer->endpoint.sockaddr_in6.sin6_flowinfo = 0;
        peer->endpoint.sockaddr_in6.sin6_scope_id = 0;
        return;
    }
    if (could_v4) {
        memcpy(buffer, host, len_host);
        buffer[len_host] = '\0';
        if (inet_pton(AF_INET, buffer, &peer->endpoint.sockaddr_in.sin_addr) == 1) {
            peer->endpoint_type = HOST_TYPE_IPV4;
            peer->endpoint.sockaddr_in.sin_family = AF_INET;
            peer->endpoint.sockaddr_in.sin_port = port;
            memset(peer->endpoint.sockaddr_in.sin_zero, 0, sizeof peer->endpoint.sockaddr_in.sin_zero);
            return;
        }
    }
    peer->endpoint_type = HOST_TYPE_DOMAIN;
    memcpy(peer->endpoint.domain.name, host, len_host);
    peer->endpoint.domain.name[len_host] = '\0';
    peer->endpoint.domain.len_name = len_host;
    peer->endpoint.domain.port = port;
}

int parse_netdev_buffer(
    struct netdev *const restrict netdev, 
    char const *const restrict buffer,
    size_t size_buffer
) {
    struct peer* peers_buffer, *peer;
    size_t line_start, line_end, stripped_start, stripped_end, len_stripped, key_end, len_key, value_start, len_value, host_end, len_port, port_start;
    enum parse_status parse_status;
    char const *key, *value;
    char buffer_port[6];
    int r;

    if (init_netdev_peers(netdev, ALLOC_BASE)) {
        return -1;
    }
    netdev->name[0] = '\0';
    netdev->len_name = 0;
    netdev->ifindex = -1;

    parse_status = parse_status_none;
    for (line_start = 0; line_start < size_buffer; line_start = line_end + 1) {
        for (line_end = line_start; line_end < size_buffer; ++line_end) {
            if (buffer[line_end] == '\n' || buffer[line_end] == '\0') break;
        }
        if (line_end < line_start + 1) continue;
        for (stripped_start = line_start; stripped_start < line_end && (buffer[stripped_start] == ' ' || buffer[stripped_start] == '\t'); ++stripped_start);
        if (buffer[stripped_start] == '#') continue;
        for (stripped_end = line_end - 1; stripped_end > stripped_start && (buffer[stripped_end] == ' ' || buffer[stripped_end] == '\t'); --stripped_end);
        if (stripped_end < stripped_start) continue;
        ++stripped_end;
        len_stripped = stripped_end - stripped_start;
        key = buffer + stripped_start;
        if (buffer[stripped_start] == '[') {
            if (buffer[stripped_end - 1] != ']') {
                println_error("Sectition title not ended");
                r = -1;
                goto free_peers;
            }
            ++key;
            if (len_stripped == (sizeof TITLE_NETDEV) + 1 &&
                !strncmp(key, TITLE_NETDEV, (sizeof TITLE_NETDEV) - 1)) 
            {
                parse_status = parse_status_netdev_section;
            } else if (len_stripped == (sizeof TITLE_PEER) + 1 &&
                !strncmp(key, TITLE_PEER, (sizeof TITLE_PEER) - 1)) 
            {
                ++netdev->peers_count;
                if (netdev->peers_count > netdev->peers_allocated) {
                    while (netdev->peers_count > netdev->peers_allocated) {
                        if (netdev->peers_allocated == USHRT_MAX) {
                            println_error("Cannot allocate more memory for peers");
                            r = -1;
                            goto free_peers;
                        } else if (netdev->peers_allocated > USHRT_MAX / 2) {
                            netdev->peers_allocated = USHRT_MAX;
                        } else {
                            netdev->peers_allocated *= 2;
                        }
                    }
                    peers_buffer = realloc(netdev->peers, sizeof *netdev->peers * netdev->peers_count);
                    if (!peers_buffer) {
                        println_error_with_errno("Failed to reallocat memory for peers");
                        r = -1;
                        goto free_peers;
                    }
                    netdev->peers = peers_buffer;
                }
                peer = netdev->peers + netdev->peers_count - 1;
                init_peer(peer);
                parse_status = parse_status_peer_section;
            } else {
                parse_status = parse_status_other_section;
            }
            continue;
        }
        // Section content
        switch (parse_status) {
        case parse_status_none:
        case parse_status_other_section:
            continue;
        default:
            break;
        }
        for (key_end = stripped_start; key_end < stripped_end; ++key_end) {
            if (buffer[key_end] == '=') break;
        }
        if (key_end <= stripped_start) continue;
        len_key = key_end - stripped_start;
        value_start = key_end + 1;
        len_value = stripped_end - value_start;
        value = buffer + value_start;
        switch (parse_status) {
        case parse_status_netdev_section:
            if (len_key == LEN_KEY_KIND) {
                if (!strncmp(key, KEY_KIND, LEN_KEY_KIND)) {
                    if (strncmp(value, VALUE_WIREGUARD, LEN_VALUE_WIREGUARD)) {
                        println_error("Netdev kind is not '"VALUE_WIREGUARD"'");
                        r = -1;
                        goto free_peers;
                    }
                } else if (!strncmp(key, KEY_NAME, LEN_KEY_NAME)) {
                    netdev->len_name = min2(len_value, (sizeof netdev->name) - 1);
                    memcpy(netdev->name, value, netdev->len_name);
                    netdev->name[netdev->len_name] = '\0';
                }
            }
            break;
        case parse_status_peer_section:
            peer = netdev->peers + netdev->peers_count - 1;
            switch (len_key) {
            case LEN_KEY_PUBLICKEY:
                if (!strncmp(key, KEY_PUBLICKEY, LEN_KEY_PUBLICKEY)) {
                    if (len_value != LEN_WGKEY_BASE64) {
                        println_error("Pubkey length is not right (%lu)", len_value);
                        r = -1;
                        goto free_peers;
                    }
                    if (!key_from_base64(peer->public_key, value)) {
                        r = -1;
                        goto free_peers;
                    }
                }
                break;
            case LEN_KEY_ENDPOINT:
                if (!strncmp(key, KEY_ENDPOINT, LEN_KEY_ENDPOINT)) {
                    for (host_end = stripped_end - 1; host_end > value_start; --host_end) {
                        if (buffer[host_end] == ':') break;
                    }
                    if (host_end <= value_start) continue; // Illegal
                    // Port
                    port_start = host_end + 1;
                    if (port_start >= stripped_end) continue; // Illegal
                    len_port = stripped_end - port_start;
                    len_port = min2(len_port, (sizeof buffer_port) - 1);
                    memcpy(buffer_port, buffer + port_start, len_port);
                    buffer_port[len_port] = '\0';
                    // Complete
                    peer_endpoint_complete(peer, value, host_end - value_start, strtoul(buffer_port, NULL, 10));
                }
                break;
            }
            break;
        default:
            break;
        }
    }
    if (!netdev->name[0]) {
        println_error("Netdev does not define a name");
        r = -1;
        goto free_peers;
    }
    if (!netdev->peers_count) {
        free(netdev->peers);
    } else if (netdev->peers_count != netdev->peers_allocated) {
        peers_buffer = realloc(netdev->peers, sizeof *netdev->peers * netdev->peers_count);
        if (!peers_buffer) {
            println_error_with_errno("Failed to shrink memory allocated for peers");
            r = -1;
            goto free_peers;
        }
        netdev->peers = peers_buffer;
    }
    netdev->peers_allocated = netdev->peers_count;
    r = 0;

free_peers:
    if (r) {
        if (netdev->peers) free(netdev->peers);
    }
    return r;
}

void peers_swap_item(
    struct peer *const restrict peers,
    unsigned short const some,
    unsigned short const other
) {
    struct peer peer;

    if (some == other) return;
    peer = peers[some];
    peers[some] = peers[other];
    peers[other] = peer;
}

unsigned short peers_partition(
    struct peer *const restrict peers,
    unsigned short const low,
    unsigned short const high
) {
    unsigned short i, j;
    uint8_t const *pivot;
    
    pivot = peers[high].public_key;
    i = low - 1;
    for (j = low; j < high; ++j) {
        if (memcmp(peers[j].public_key, pivot, LEN_WGKEY_RAW) < 0) {
            peers_swap_item(peers, ++i, j);
        }
    }
    peers_swap_item(peers, ++i, high);
    return i;

}

void peers_quick_sort(
    struct peer *const restrict peers,
    unsigned short const low,
    unsigned short const high
) {
    unsigned short pivot;

    if (low >= high) return;
    pivot = peers_partition(peers, low, high);
    if (pivot) peers_quick_sort(peers, low, pivot - 1);
    peers_quick_sort(peers, pivot + 1, high);
}

void sort_netdev_peers(
    struct netdev *const restrict netdev
) {
    if (!netdev->peers_count) return;
    peers_quick_sort(netdev->peers, 0, netdev->peers_count - 1);
}

#ifndef dump_netdev
void dump_netdev(
    struct netdev const *const restrict netdev
) {
    unsigned short i;
    struct peer const *peer;

    println_info("Netdev '%s':", netdev->name);
    for (i = 0; i < netdev->peers_count; ++i) {
        println_info(" => Peer %hu:", i);
        peer = netdev->peers + i;
        // println_info("  -> Public Key: %s", peer->public_key);
        // println_info("  -> Host: %s", peer->endpoint_host);
        println_info("  -> Host type: %s", host_type_strings[peer->endpoint_type]);
        // println_info("  -> Port: %hu", peer->endpoint_port);
    }
}
#endif

int parse_netdev_config(
    struct netdev *const restrict netdev, 
    int const fd_netdev
) {
    char *buffer;
    off_t size_file;
    ssize_t size_read;
    int r;

    size_file = lseek(fd_netdev, 0, SEEK_END);
    if (size_file < 0) {
        println_error_with_errno("Failed to seek to end of config file");
        return -1;
    }
    if (size_file == 0) {
        println_error("Config file is empty");
        return -1;
    }
    if (lseek(fd_netdev, 0, SEEK_SET)) {
        println_error_with_errno("Failed to seek to start of config file");
        return -1;
    }
    buffer = malloc(size_file + 1);
    if (!buffer) {
        println_error_with_errno("Failed to allocate memory for buffer to read config file");
        return -1;
    }
    size_read = read(fd_netdev, buffer, size_file);
    if (size_read < 0) {
        println_error_with_errno("Failed to read content of config file");
        r = -1;
        goto free_buffer;
    }
    if (size_read != size_file) {
        println_error("Read size (%ld) != expected size (%ld)", size_read, size_file);
        r = -1;
        goto free_buffer;
    }
    buffer[size_file] = '\0';
    if (parse_netdev_buffer(netdev, buffer, size_file)) {
        println_error("Failed to parse config buffer");
        r = -1;
        goto free_buffer;
    }
    sort_netdev_peers(netdev);
    dump_netdev(netdev);
    r = 0;
free_buffer:
    free(buffer);
    return r;
}

int read_netdev_configs(
    struct netdev *const restrict netdevs,
    unsigned short const netdevs_count,
    char *netdev_stems[]
) {
    char netdev_name[NAME_MAX + 1];
    char const *netdev_stem;
    size_t len_netdev_stem;
    unsigned short i, j;
    int r, fd_configs, fd_netdev;

    fd_configs = open(PATH_CONFIGS, O_RDONLY | O_DIRECTORY);
    if (fd_configs < 0) {
        println_error_with_errno("Failed to open configs dir '"PATH_CONFIGS"'");
        return -1;
    }
    for (i = 0; i < netdevs_count; ++i) {
        netdev_stem = netdev_stems[i];
        len_netdev_stem = strnlen(netdev_stem, NETDEV_STEM_MAX);
        if (len_netdev_stem >= NETDEV_STEM_MAX) {
            println_error("Netdev name too long (%lu: '%s')", len_netdev_stem, netdev_stem);
            r = -1;
            goto close_configs;
        }
        memcpy(netdev_name, netdev_stem, len_netdev_stem);
        memcpy(netdev_name + len_netdev_stem, ".netdev", 8);
        println_info("Opening netdev config file '%s'", netdev_name);
        fd_netdev = openat(fd_configs, netdev_name, O_RDONLY);
        if (fd_netdev < 0) {
            println_error_with_errno("Failed to open netdev config file '%s'", netdev_name);
            r = -1;
            goto close_configs;
        }
        r = parse_netdev_config(netdevs + i, fd_netdev);
        if (close(fd_netdev)) {
            println_error_with_errno("Failed to close netdev config file '%s'", netdev_name);
            r = -1;
        }
        for (j = 0; j < i; ++j) {
            if (!strncmp(netdevs[i].name, netdevs[j].name, sizeof netdevs->name)) {
                println_error("Duplicated config for interface '%s'", netdevs[i].name);
                r = -1;
            }
        }
        if (r) {
            goto close_configs;
        }
    }
    r = 0;
close_configs:
    if (close(fd_configs)) {
        println_error_with_errno("Failed to close configs dir '"PATH_CONFIGS"'");
        r = -1;
    }
    return r;
}

struct peer_with_public_status {
    struct peer *const restrict peer;
    bool with_pubkey;
};

static int parse_peer(
    struct nlattr const *const restrict attr, 
    void *data
) {
    struct peer_with_public_status *const restrict peer_with_public_status = data;
    struct peer *const restrict peer = peer_with_public_status->peer;

    struct sockaddr *addr;

	switch (mnl_attr_get_type(attr)) {
	case WGPEER_A_PUBLIC_KEY:
		if (mnl_attr_get_payload_len(attr) == LEN_WGKEY_RAW) {
			memcpy(peer->public_key, mnl_attr_get_payload(attr), LEN_WGKEY_RAW);
            peer_with_public_status->with_pubkey = true;
        } else {
            println_warn("Public key length not right: %hu", mnl_attr_get_payload_len(attr));
        }
		break;
	case WGPEER_A_ENDPOINT:
		if (mnl_attr_get_payload_len(attr) < sizeof *addr)
			break;
		addr = mnl_attr_get_payload(attr);
		if (addr->sa_family == AF_INET && mnl_attr_get_payload_len(attr) == sizeof(struct sockaddr_in)) {
            peer->endpoint_type = HOST_TYPE_IPV4;
            peer->endpoint.sockaddr_in = *(struct sockaddr_in *)addr;
        } else if (addr->sa_family == AF_INET6 && mnl_attr_get_payload_len(attr) == sizeof(struct sockaddr_in6)) {
            peer->endpoint_type = HOST_TYPE_IPV6;
            peer->endpoint.sockaddr_in6 = *(struct sockaddr_in6 *)addr;
        } else {
            println_warn("Endpoint is neither v4 nor v6");
        }
		break;
	case WGPEER_A_LAST_HANDSHAKE_TIME:
		if (mnl_attr_get_payload_len(attr) == sizeof(peer->last_handshake)) {
			memcpy(&peer->last_handshake, mnl_attr_get_payload(attr), sizeof(peer->last_handshake));
        } else {
            println_warn("Last handshake time size not right");
        }
		break;
    default:
        break;
	}
	return MNL_CB_OK;
}

int parse_peers(
    struct nlattr const *const restrict attr, 
    void *data
) {
    struct netdev *const restrict interface = data;
    struct peer *const restrict peer = interface->peers + interface->peers_count;
    int r;
    
    ++interface->peers_count;
    if (interface->peers_count > interface->peers_allocated) {
        println_error("More peers on interface than config (at least %hu > %hu)", interface->peers_count, interface->peers_allocated);
        return MNL_CB_ERROR;
    }
    init_peer(peer);
    struct peer_with_public_status peer_with_public_status = {peer, false};
    r = mnl_attr_parse_nested(attr, parse_peer, &peer_with_public_status);
	if (!r) return r;
    if (!peer_with_public_status.with_pubkey) {
        println_error("Peer public key is empty");
        return MNL_CB_ERROR;
    }
	return MNL_CB_OK;
}

int parse_interface(
    struct nlattr const *const restrict attr, 
    void *data
) {
	struct netdev *restrict interface;

    interface = data;
	switch (mnl_attr_get_type(attr)) {
	case WGDEVICE_A_IFINDEX:
		if (!mnl_attr_validate(attr, MNL_TYPE_U32))
			interface->ifindex = mnl_attr_get_u32(attr);
		break;
	case WGDEVICE_A_PEERS:
		return mnl_attr_parse_nested(attr, parse_peers, interface);
	}
    return MNL_CB_OK;
}


int get_interface_callback(
    struct nlmsghdr const *const restrict message_header, 
    void *const restrict data
) {
	return mnl_attr_parse(message_header, sizeof(struct genlmsghdr), parse_interface, data);
}

int get_interface_peers(
    struct netdev *const restrict interface
) {
	struct mnlg_socket *generic_socket;
	struct nlmsghdr *message_header;
    int r, last_error;

    last_error = EINTR;
    do {
        interface->peers_count = 0;
        interface->ifindex = -1;
        generic_socket = mnlg_socket_open(WG_GENL_NAME, WG_GENL_VERSION);
        if (!generic_socket) {
            println_error_with_errno("Failed to open generic socket '%s'", WG_GENL_NAME);
            return -1;
        }

        message_header = mnlg_msg_prepare(generic_socket, WG_CMD_GET_DEVICE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);
        mnl_attr_put_strz(message_header, WGDEVICE_A_IFNAME, interface->name);
        if (mnlg_socket_send(generic_socket, message_header) < 0) {
            println_error_with_errno("Failed to send message to get wireguard interface");
            last_error = errno;
            r = -1;
            goto close_socket;
        }
        errno = 0;
        if (mnlg_socket_recv_run(generic_socket, get_interface_callback, interface) < 0) {
            if errno {
                println_error_with_errno("Failed to run get_interface_callback");
                last_error = errno;
            } else {
                println_error("Failed to run get_interface_callback");
                last_error = EINVAL;
            }
            r = -1;
        } else {
            sort_netdev_peers(interface);
            r = 0;
        }
        close_socket:
            mnlg_socket_close(generic_socket);
        break;
    } while (last_error == EINTR);
    return r;
}

// int update_ipv4(
//     // struct 

// ) {

// }

// int update_ipv6(

// )

int update_peer_endpoint(
    struct netdev_no_peers const *const restrict netdev_no_peers,
    uint8_t const public_key[LEN_WGKEY_RAW],
    union sockaddr_in46 const *const restrict address,
    enum host_type const type
) {
    struct mnlg_socket *generic_socket;
	struct nlmsghdr *message_header;
    struct nlattr *peers_nest, *peer_nest;
    char public_key_base64[LEN_WGKEY_BASE64 + 1];
    char ip_address[LEN_IPV6_STRING + 1];
    int r;

    key_to_base64(public_key_base64, public_key);
    print_info("Updating interface '%s' (ifindex %hu) peer '%s' endpoint to: ", 
        netdev_no_peers->name, netdev_no_peers->ifindex, public_key_base64);
    switch (type) {
    case HOST_TYPE_IPV6:
        ipv6_string_from_in6(ip_address, &address->sockaddr_in6.sin6_addr);
        println("[%s]:%hu", ip_address, ntohs(address->sockaddr_in6.sin6_port));
        break;
    case HOST_TYPE_IPV4:
        ipv4_string_from_in(ip_address, &address->sockaddr_in.sin_addr);
        println("%s:%hu", ip_address, ntohs(address->sockaddr_in.sin_port));
        break;
    default:
        println_error("\nIllegal host type %d (%s)", type, host_type_strings[type]);
        return -1;
    }
    

    generic_socket = mnlg_socket_open(WG_GENL_NAME, WG_GENL_VERSION);
    if (!generic_socket) {
        println_error_with_errno("Failed to open generic socket '%s'", WG_GENL_NAME);
        return -1;
    }
    message_header = mnlg_msg_prepare(generic_socket, WG_CMD_SET_DEVICE, NLM_F_REQUEST | NLM_F_ACK);
    if (!message_header) {
        println_error("Failed to prepare message header");
        r = -1;
        goto close_socket;
    }
    if (netdev_no_peers->ifindex == (typeof(netdev_no_peers->ifindex))-1) {
        mnl_attr_put_u32(message_header, WGDEVICE_A_IFINDEX, netdev_no_peers->ifindex);
    } else {
        mnl_attr_put_strz(message_header, WGDEVICE_A_IFNAME, netdev_no_peers->name);
    }
    peers_nest = mnl_attr_nest_start(message_header, WGDEVICE_A_PEERS);
    if (!peers_nest) {
        println_error("Message too big for modifying peers");
        r = -1;
        goto close_socket;
    }
    peer_nest = mnl_attr_nest_start_check(message_header, SOCKET_BUFFER_SIZE, 0);
    if (!peer_nest) {
        println_error("Message too big for modifying peer");
        r = -1;
        goto close_socket;
    }
    if (!mnl_attr_put_check(message_header, SOCKET_BUFFER_SIZE, WGPEER_A_PUBLIC_KEY, LEN_WGKEY_RAW, public_key)) {
        print_error("Message too big for specifying peer");
        r = -1;
        goto close_socket;
    }
    switch (type) {
    case HOST_TYPE_IPV6: 
        if (!mnl_attr_put_check(message_header, SOCKET_BUFFER_SIZE, WGPEER_A_ENDPOINT, sizeof address->sockaddr_in6, &address->sockaddr_in6)) {
            println_error("Failed to append message to update endpoint to IPv6");
            r = -1;
            goto close_socket;
        }
        break;
    case HOST_TYPE_IPV4:
        if (!mnl_attr_put_check(message_header, SOCKET_BUFFER_SIZE, WGPEER_A_ENDPOINT, sizeof address->sockaddr_in, &address->sockaddr_in)) {
            println_error("Failed to append message to update endpoint to IPv4");
            r = -1;
            goto close_socket;
        }
        break;
    default:
        println_error("Illegal host type %d (%s)", type, host_type_strings[type]);
        r = -1;
        goto close_socket;
    }
    mnl_attr_nest_end(message_header, peer_nest);
	mnl_attr_nest_end(message_header, peers_nest);
	if (mnlg_socket_send(generic_socket, message_header) < 0) {
        println_error_with_errno("Failed to send message over socket");
        r = -1;
        goto close_socket;
	}
	errno = 0;
	if (mnlg_socket_recv_run(generic_socket, NULL, NULL) < 0) {
        println_error_with_errno("Failed to receive message from socket");
        r = -1;
        goto close_socket;
	}
    r = 0;
close_socket:
    mnlg_socket_close(generic_socket);
    return r;
}

int update_netdev(
    struct netdev const *const restrict netdev,
    struct netdev *const restrict interface
) {
    unsigned short i;
    struct peer const *restrict peer_netdev, *restrict peer_interface;
    struct addrinfo *addrinfos, *addrinfo;
    enum host_type looked_up_type;
    union sockaddr_in46 looked_up_address;

    if (!netdev->peers_count) return 0;
    // Init buffer interface
    memcpy(interface->name, netdev->name, netdev->len_name + 1);
    interface->len_name = netdev->len_name;
    if (get_interface_peers(interface)) {
        println_error("Failed to get interface '%s' peers", interface->name);
        return -1;
    }
    if (interface->peers_count != netdev->peers_count) {
        println_error("Interface peers count (%hu) != netdev peers count (%hu)",
            interface->peers_count, netdev->peers_count);
        return -1;
    }
    for (i = 0; i < netdev->peers_count; ++i) {
        peer_netdev = netdev->peers + i;
        // No need to update non-domain endpoints
        if (peer_netdev->endpoint_type != HOST_TYPE_DOMAIN) continue;
        peer_interface = interface->peers + i;
        if (memcmp(peer_netdev->public_key, peer_interface->public_key, LEN_WGKEY_RAW)) {
            println_error("Peer different on interface");
            return -1;
        }
        looked_up_type = peer_netdev->endpoint_type;
        switch (peer_netdev->endpoint_type) {
        case HOST_TYPE_DOMAIN:
            if (getaddrinfo(peer_netdev->endpoint.domain.name, NULL, NULL, &addrinfos)) {
                println_warn("Failed to resolve DNS for '%s'", peer_netdev->endpoint.domain.name);
                continue;
            }
            for (addrinfo = addrinfos; looked_up_type == HOST_TYPE_DOMAIN && addrinfo; addrinfo = addrinfo->ai_next) {
                switch (addrinfo->ai_family) {
                case AF_INET:
                    looked_up_type = HOST_TYPE_IPV4;
                    looked_up_address.sockaddr_in = *(struct sockaddr_in *)addrinfo->ai_addr;
                    looked_up_address.sockaddr_in.sin_port = peer_netdev->endpoint.domain.port;
                    break;
                case AF_INET6:
                    looked_up_type = HOST_TYPE_IPV6;
                    looked_up_address.sockaddr_in6 = *(struct sockaddr_in6 *)addrinfo->ai_addr;
                    looked_up_address.sockaddr_in6.sin6_port = peer_netdev->endpoint.domain.port;
                    break;
                default:
                    break;
                }
            }
            freeaddrinfo(addrinfos);
            if (looked_up_type == HOST_TYPE_DOMAIN) {
                println_warn("Failed to lookup domain '%s'", peer_netdev->endpoint.domain.name);
                continue;
            }
            break;
        case HOST_TYPE_IPV4:
            looked_up_address.sockaddr_in = peer_netdev->endpoint.sockaddr_in;
            break;
        case HOST_TYPE_IPV6:
            looked_up_address.sockaddr_in6 = peer_netdev->endpoint.sockaddr_in6;
            break;
        }
        if (peer_interface->endpoint_type == looked_up_type &&
            sockaddr_in46_equal(&peer_interface->endpoint.sockaddr_in46, &looked_up_address, looked_up_type)
        ) {
            continue;
        }
        if (update_peer_endpoint(&interface->netdev_no_peers, peer_interface->public_key, &looked_up_address, looked_up_type)) {
            println_warn("Failed to update, wait till next loop...");
            continue;
        }
    }
	return 0;
}

int update_netdevs_forever(
    struct netdev const *const restrict netdevs,
    unsigned short const netdevs_count,
    unsigned short const interval
) {
    struct netdev interface;
    struct netdev const *netdev;
    unsigned short i, max_peers;

    max_peers = 0;
    for (i = 0; i < netdevs_count; ++i) {
        netdev = netdevs + i;
        if (netdev->peers_count > max_peers) max_peers = netdev->peers_count;
    }
    if (!max_peers) {
        println_error("No peers defined for any interface");
        return -1;
    }
    if (init_netdev_peers(&interface, max_peers)) {
        return -1;
    }
    println_info("Updating forever with %hu seconds interval for %hu netdev(s)", 
        interval, netdevs_count);
    for(;;) {
        max_peers = 0;
        for (i = 0; i < netdevs_count; ++i) {
            netdev = netdevs + i;
            // println_info("Updating netdev '%s'...", netdev->name);
            if (update_netdev(netdev, &interface)) {
                free(interface.peers);
                return -1;
            }
            dump_netdev(&interface);
        }
        sleep(interval);
    }    
}

void show_help(char const *const restrict arg0) {
    printf("%s", arg0);
    puts(" (--interval/-i [interval]) [netdev name] ([netdev name] ([netdev name] ...))\n\n"
        "\t--interval/-i [interval]\tset the interval between each check\n"
        "\t[netdev name]\t\t\tnetdev names under '"PATH_CONFIGS"', without .netdev suffix\n"
    );
}

void show_version() {
    printf("sd-networkd-wg-ddns version %s by Guoxin \"7Ji\" Pu, licensed under GNU Affero General Public License v3 or later\n", version);
}

int main(int argc, char *argv[]) {
    struct netdev *netdevs;
    unsigned short interval = 10;
    int c, option_index = 0, netdevs_count;
    // char const *const arg0 = argv[0];l
    struct option const long_options[] = {
        {"interval",    required_argument,  NULL,   'i'},
        {"help",        no_argument,        NULL,   'h'},
        {"version",     no_argument,        NULL,   'v'},
        {NULL,          no_argument,        NULL,     0},
    };

    while ((c = getopt_long(argc, argv, "i:hv", long_options, &option_index)) != -1) {
        switch (c) {
        case 'i':
            interval = strtoul(optarg, NULL, 10);
            break;
        case 'v':   // version
            show_version();
            return 0;
        case 'h':   // help
            show_help(argv[0]);
            return 0;
        default:
            println_error("Unknown option '%s'", argv[optind - 1]);
            return -1;
        }
    }

    netdevs_count = argc - optind;
    if (netdevs_count < 1) {
        println_error("Too few arguments, please pass .netdev names (without suffix) as arguments");
        return -1;
    }
    netdevs = malloc(sizeof *netdevs * netdevs_count);
    if (!netdevs) {
        println_error_with_errno("Failed to allocate memory on heap for %hu netdevs", netdevs_count);
        return -1;
    }
    if (read_netdev_configs(netdevs, netdevs_count, argv + optind)) {
        println_error("Failed to read netdev configs");
        goto free_netdevs;
    }
    if (!interval) interval = 10;
    if (update_netdevs_forever(netdevs, netdevs_count, interval)) {
        println_error("Failed to update netdevs");
        goto free_netdevs;
    }
free_netdevs:
    free(netdevs);
    return -1; // There's no normal exit, any exit means error
}