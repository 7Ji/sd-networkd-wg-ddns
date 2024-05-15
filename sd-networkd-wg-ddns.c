/* C */
#include <asm-generic/errno-base.h>
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
#include <unistd.h>
/* Linux */
#include <linux/if.h>
#include <linux/limits.h>
#include <linux/wireguard.h>
/* Network */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* Library */
#include "libmnl_minimized.h"

#define println_with_prefix_and_source(prefix, format, arg...) \
    printf("["prefix"] %s:%d: "format"\n", __FUNCTION__, __LINE__, ##arg)
#define println_with_prefix(prefix, format, arg...) \
    printf("["prefix"] "format"\n", ##arg)
#define println_info(format, arg...) println_with_prefix("INFO", format, ##arg)
#define println_warn(format, arg...) println_with_prefix("WARN", format, ##arg)
#define println_error(format, arg...)  \
    println_with_prefix_and_source("ERROR", format, ##arg)
#define println_error_with_errno(format, arg...) \
    println_error(format", errno: %d, error: %s\n", ##arg, errno, strerror(errno))

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
#define LEN_KEY_RAW 32
#define LEN_KEY_BASE64 ((((LEN_KEY_RAW) + 2) / 3) * 4)

enum host_type {
    host_type_domain,
    host_type_ipv4,
    host_type_ipv6
};

char *host_type_strings[] = {
    "domain",
    "IPv4",
    "IPv6"
};

struct endpoint_domain {
    char name[LEN_DOMAIN + 1]; // len = 255 (max length of domain name)
    unsigned short len_name;
    in_port_t port;
};

struct peer {
    uint8_t public_key[LEN_KEY_RAW]; // len = 44
    union {
        struct {
            char domain[LEN_DOMAIN + 1];
            unsigned short len_domain;
        };
        struct in6_addr ipv6;
        struct in_addr ipv4;
    } endpoint_host;
    in_port_t endpoint_port;
    enum host_type endpoint_type;
    struct timespec last_handshake;
};

struct netdev {
    char name[IFNAMSIZ]; // len = 15
    unsigned short len_name;
    uint32_t ifindex;
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
    peer->endpoint_host.domain[0] = '\0';
    peer->endpoint_host.len_domain = 0;
    peer->endpoint_port = 0;
    peer->endpoint_type = host_type_domain;
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

void key_to_base64(char base64[static LEN_KEY_BASE64 + 1], const uint8_t key[static LEN_KEY_RAW])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN / 3; ++i)
		encode_base64(&base64[i * 4], &key[i * 3]);
	encode_base64(&base64[i * 4], (const uint8_t[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
	base64[LEN_KEY_BASE64 - 1] = '=';
	base64[LEN_KEY_BASE64] = '\0';
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

bool key_from_base64(uint8_t key[static LEN_KEY_RAW], const char *base64)
{
	unsigned int i;
	volatile uint8_t ret = 0;
	int val;

	if (base64[LEN_KEY_BASE64 - 1] != '=')
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

void peer_endpoint_fill_host(
    struct peer *const restrict peer,
    char const *const restrict host,
    unsigned short len_host
) {
    bool could_v4;
    char buffer[LEN_DOMAIN + 1];

    len_host = min2(len_host, (sizeof buffer) - 1);
    if (host[0] == '[' && host[len_host] == ']') { // Definitely not v4
        could_v4 = false;
    } else {
        could_v4 = true;
    }
    memcpy(buffer, host + 1, len_host - 2);
    buffer[len_host - 2] = '\0';
    if (inet_pton(AF_INET6, buffer, &peer->endpoint_host.ipv6) == 1) { // Is v6
        peer->endpoint_type = host_type_ipv6;
        return;
    }
    if (could_v4) {
        memcpy(buffer, host, len_host);
        buffer[len_host] = '\0';
        if (inet_pton(AF_INET, buffer, &peer->endpoint_host.ipv4) == 1) {
            peer->endpoint_type = host_type_ipv4;
            return;
        }
    }
    memcpy(peer->endpoint_host.domain, host, len_host);
    peer->endpoint_host.domain[len_host] = '\0';
    peer->endpoint_host.len_domain = len_host;
    peer->endpoint_type = host_type_domain;
}

int parse_netdev_buffer(
    struct netdev *const restrict netdev, 
    char const *const restrict buffer,
    size_t size_buffer
) {
    struct peer* peers_buffer, *peer;
    size_t line_start, line_end, stripped_start, stripped_end, len_stripped, key_end, len_key, value_start, len_value, host_end, host_start, len_host, len_port, port_start;
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
                    if (len_value != LEN_KEY_BASE64) {
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
                    peer->endpoint_port = strtoul(buffer_port, NULL, 10);
                    // Host
                    peer_endpoint_fill_host(peer, value, host_end - value_start);
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
    char const *pivot;
    
    pivot = peers[high].public_key;
    i = low - 1;
    for (j = low; j < high; ++j) {
        if (strncmp(peers[j].public_key, pivot, (sizeof peers->public_key) - 1) < 0) {
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
    peers_quick_sort(netdev->peers, 0, netdev->peers_count - 1);
}

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
    char const *const restrict netdev_stems[]
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
		if (mnl_attr_get_payload_len(attr) == LEN_KEY_RAW) {
			memcpy(peer->public_key, mnl_attr_get_payload(attr), LEN_KEY_RAW);
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
            peer->endpoint_type = host_type_ipv4;
            peer->endpoint_host.ipv4 = ((struct sockaddr_in *)addr)->sin_addr;
            peer->endpoint_port = ((struct sockaddr_in *)addr)->sin_port;
        } else if (addr->sa_family == AF_INET6 && mnl_attr_get_payload_len(attr) == sizeof(struct sockaddr_in6)) {
            peer->endpoint_type = host_type_ipv6;
            peer->endpoint_host.ipv6 = ((struct sockaddr_in6 *)addr)->sin6_addr;
            peer->endpoint_port = ((struct sockaddr_in6 *)addr)->sin6_port;
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
    while (last_error == EINTR) {
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
            r = 0;
        }
        close_socket:
            mnlg_socket_close(generic_socket);
        break;
    }
    return r;
}


int update_netdev(
    struct netdev const *const restrict netdev,
    struct netdev *const restrict interface
) {
    unsigned short i;
    struct peer const *restrict peer_netdev, *restrict peer_interface;
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
        if (peer_netdev->endpoint_type != host_type_domain) continue;
        peer_interface = interface->peers + i;
        // 
        switch (peer_interface->endpoint_type) {
        case host_type_ipv4:
            break;
        case host_type_ipv6:
            break;
        default:
            break;
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
    if (init_netdev_peers(&interface, max_peers)) {
        return -1;
    }
    for(;;) {
        max_peers = 0;
        for (i = 0; i < netdevs_count; ++i) {
            netdev = netdevs + i;
            println_info("Updating netdev '%s'...", netdev->name);
            if (update_netdev(netdev, &interface)) {
                free(interface.peers);
                return -1;
            }
            dump_netdev(&interface);
        }
        sleep(interval);
    }    
}

int main(int argc, char const *argv[]) {
    struct netdev *netdevs;
    unsigned short netdevs_count;

    if (argc < 2) {
        println_error("Too few arguments, please pass .netdev names (without suffix) as arguments");
        return -1;
    }
    netdevs_count = argc - 1;
    netdevs = malloc(sizeof *netdevs * netdevs_count);
    if (!netdevs) {
        println_error_with_errno("Failed to allocate memory on heap for %hu netdevs", netdevs_count);
        return -1;
    }
    if (read_netdev_configs(netdevs, netdevs_count, argv + 1)) {
        println_error("Failed to read netdev configs");
        goto free_netdevs;
    }
    if (update_netdevs_forever(netdevs, netdevs_count, 10)) {
        println_error("Failed to update netdevs");
        goto free_netdevs;
    }
free_netdevs:
    free(netdevs);
    return -1; // There's no normal exit, any exit means error
}