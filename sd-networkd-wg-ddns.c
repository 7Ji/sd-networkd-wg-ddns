// WIP, DO NOT USE

#include <limits.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

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

struct peer {
    char public_key[45]; // len = 44
    char endpoint_host[256]; // len = 255 (max length of domain name)
    unsigned short endpoint_port;
    unsigned short len_public_key;
    unsigned short len_endpoint_host;
    unsigned long latest_handshake;
};

struct netdev {
    char name[16]; // len = 15
    unsigned short len_name;
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

    netdev->peers = malloc(sizeof *netdev->peers * 0x10);
    if (!netdev->peers) {
        println_error_with_errno("Failed to allocate memory for peers");
        return -1;
    }
    netdev->peers_allocated = 0x10;
    netdev->peers_count = 0;
    netdev->name[0] = '\0';
    netdev->len_name = 0;

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
        // printf("Line (%lu): '", len_stripped);
        // for (size_t i = stripped_start; i < stripped_end; ++i) {
        //     putchar(buffer[i]);
        // }
        // printf("'\n");
        // Section title
        key = buffer + stripped_start;
        if (buffer[stripped_start] == '[') {
            if (buffer[stripped_end - 1] != ']') {
                println_error("Sectition title not ended");
                r = -1;
                goto free_peers;
            }
            ++key;
            if (len_stripped == sizeof TITLE_NETDEV + 1 &&
                !strncmp(key, TITLE_NETDEV, sizeof TITLE_NETDEV - 1)) 
            {
                parse_status = parse_status_netdev_section;
            } else if (len_stripped == sizeof TITLE_PEER + 1 &&
                !strncmp(key, TITLE_PEER, sizeof TITLE_PEER - 1)) 
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
                peer->latest_handshake = 0;
                peer->endpoint_host[0] = '\0';
                peer->len_endpoint_host = 0;
                peer->endpoint_port = 0;
                peer->public_key[0] = '\0';
                peer->len_public_key = 0;
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
                    netdev->len_name = min2(len_value, sizeof netdev->name - 1);
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
                    peer->len_public_key = min2(len_value, sizeof peer->public_key - 1);
                    memcpy(peer->public_key, value, peer->len_public_key);
                    peer->public_key[peer->len_public_key] = '\0';
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
                    // Host
                    host_start = value_start;
                    if (buffer[host_start] == '[' && buffer[host_end - 1] == ']') {
                        ++host_start;
                        --host_end;
                        if (host_end <= host_start) continue; // Illegal
                    }
                    len_host = host_end - value_start;
                    // Read
                    len_port = min2(len_port, sizeof buffer_port - 1);
                    memcpy(buffer_port, buffer + port_start, len_port);
                    buffer_port[len_port] = '\0';
                    if (sscanf(buffer + host_end + 1, "%hu", &peer->endpoint_port) != 1) {
                        println_error("Endpoint port ('%s') could not be parsed", buffer_port);
                        continue;
                    }
                    peer->len_endpoint_host = min2(len_host, sizeof peer->endpoint_host - 1);
                    memcpy(peer->endpoint_host, value, peer->len_endpoint_host);
                    peer->endpoint_host[peer->len_endpoint_host] = '\0';
                }
                break;
            }
            break;
        default:
            break;
        }
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

void dump_netdev(
    struct netdev const *const restrict netdev
) {
    unsigned short i;
    struct peer const *peer;

    println_info("Netdev '%s':", netdev->name);
    for (i = 0; i < netdev->peers_count; ++i) {
        println_info(" => Peer %hu:", i);
        peer = netdev->peers + i;
        println_info("  -> Public Key: %s", peer->public_key);
        println_info("  -> Host: %s", peer->endpoint_host);
        println_info("  -> Port: %hu", peer->endpoint_port);
    }
}

int parse_netdev_config(
    struct netdev *const restrict netdev, 
    int const fd_netdev
) {
    char buffer_stack[SIZE_BUFFER];
    char *buffer_heap = NULL;
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
    if (size_file >= SIZE_BUFFER) {
        buffer_heap = malloc(size_file + 1);
        if (!buffer_heap) {
            println_error_with_errno("Failed to allocate memory for buffer to read config file");
            return -1;
        }
        buffer = buffer_heap;
    } else {
        buffer = buffer_stack;
    }
    size_read = read(fd_netdev, buffer, size_file);
    if (size_read < 0) {
        println_error_with_errno("Failed to read content of config file");
        r = -1;
        goto free_heap;
    }
    if (size_read != size_file) {
        println_error("Read size (%ld) != expected size (%ld)", size_read, size_file);
        r = -1;
        goto free_heap;
    }
    buffer[size_file] = '\0';
    if (parse_netdev_buffer(netdev, buffer, size_file)) {
        println_error("Failed to parse config buffer");
        r = -1;
        goto free_heap;
    }
    dump_netdev(netdev);
    r = 0;
free_heap:
    if (buffer_heap) free(buffer_heap);
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
    unsigned short i;
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

int work(
    struct netdev const *const restrict netdevs,
    unsigned short const netdevs_count
) {
    unsigned short i;

    for (i = 0; i < netdevs_count; ++i) {
        println_info("Checking netdev '%s'...", netdevs[i].name);
    }
    return 0;
}

int main(int argc, char const *argv[]) {
    struct netdev netdevs_stack[0x10];
    struct netdev *netdevs_heap = NULL;
    struct netdev *netdevs;
    unsigned short netdevs_count;

    if (argc < 2) {
        println_error("Too few arguments, please pass .netdev names (without suffix) as arguments");
        return -1;
    }
    netdevs_count = argc - 1;
    if (netdevs_count > 0x10) {
        netdevs_heap = malloc(sizeof *netdevs_heap * netdevs_count);
        if (!netdevs_heap) {
            println_error_with_errno("Failed to allocate memory on heap for %hu netdevs", netdevs_count);
            return -1;
        }
        netdevs = netdevs_heap;
    } else {
        netdevs = netdevs_stack;
    }
    if (read_netdev_configs(netdevs, netdevs_count, argv + 1)) {
        println_error("Failed to read netdev configs");
        goto free_heap;
    }
    for(;;) {
        if (work(netdevs, netdevs_count)) {
            println_error("Failed to work");
            goto free_heap;
        }
        sleep(10);
    }
free_heap:
    if (netdevs_heap) free(netdevs_heap);
    return -1; // There's no normal exit, any exit means error
}