// WIP, DO NOT USE

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
#define SIZE_BUFFER 0x100000

#define PATH_CONFIGS "/etc/systemd/network"
// #define LEN_PATH_CONFIGS sizeof(PATH_CONFIGS) - 1
// #define CONFIG_NAME_MAXLEN PATH_MAX - sizeof(PATH_CONFIGS) + 1
#define NETDEV_STEM_MAX NAME_MAX - 6 // including terminating '\0', NAME_MAX + 1 - 7

struct peer {
    char public_key[45]; // len = 44
    char endpoint[48]; // len = 47 = 2([]) + 8x4 + 7 (IPv6) + 1 + 5 (port)
    unsigned long latest_handshake;
};

struct netdev {
    char name[16]; // len = 15
    struct peer *peers;
    unsigned short peers_count;
    unsigned short peers_allocated;
};

enum read_status {
    none,
    section_title,
    section_line
};

int parse_netdev_buffer(
    struct netdev *const restrict netdev, 
    char const *const restrict buffer,
    size_t size_buffer
) {
    struct peer* peers_buffer;
    size_t line_start, line_end, stripped_start, stripped_end, len_stripped;
    int r;

    netdev->peers = malloc(sizeof *netdev->peers * 0x10);
    if (!netdev->peers) {
        println_error_with_errno("Failed to allocate memory for peers");
        return -1;
    }
    netdev->peers_allocated = 0x10;
    netdev->peers_count = 0;
    netdev->name[0] = '\0';

    for (line_start = 0; line_start < size_buffer; line_start = line_end + 1) {
        for (line_end = line_start; line_end < size_buffer; ++line_end) {
            if (buffer[line_end] == '\n' || buffer[line_end] == '\0') break;
        }
        if (line_end <= line_start + 1) continue;
        for (stripped_start = line_start; stripped_start < line_end && (buffer[stripped_start] == ' ' || buffer[stripped_start] == '\t'); ++stripped_start);
        if (buffer[stripped_start] == '#') continue;
        for (stripped_end = line_end - 1; stripped_end > stripped_start && (buffer[stripped_end] == ' ' || buffer[stripped_end] == '\t'); --stripped_end);
        ++stripped_end;
        len_stripped = stripped_end - stripped_start;
        if (!len_stripped) continue;
        // This is currently the stripped line
        // printf("Line (%lu): '", len_stripped);
        // for (size_t i = stripped_start; i < stripped_end; ++i) {
        //     putchar(buffer[i]);
        // }
        // printf("'\n");
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