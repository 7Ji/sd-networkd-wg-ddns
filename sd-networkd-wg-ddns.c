// WIP, DO NOT USE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

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
#define size_buffer 0x100000

struct peer {
    char public_key[45]; // len = 44
    char endpoint[48]; // len = 47 = 2([]) + 8x4 + 7 (IPv6) + 1 + 5 (port)
    unsigned long latest_handshake;
};

struct netdev {
    char name[16]; // len = 15
    struct peer *peers;
};

enum read_status {
    none,
    section_title,
    section_line
};

int read_systemd_networkd_netdev_config(
    struct netdev *const restrict netdev, 
    char const *const restrict path_config
) {
    int fd_config;
    off_t size_file;
    ssize_t size_read;
    char buffer_stack[size_buffer];
    char *buffer_heap = NULL;
    char *buffer;
    int r;
    ssize_t i;

    fd_config = open(path_config, O_RDONLY);
    if (fd_config < 0) {
        println_error_with_errno("Failed to open systemd-networkd .netdev file '%s'", path_config);
        return -1;
    }
    size_file = lseek(fd_config, 0, SEEK_END);
    if (size_file < 0) {
        println_error_with_errno("Failed to seek to end of config file '%s'", path_config);
        r = -1;
        goto close_fd;
    }
    if (size_file == 0) {
        println_error("Config file '%s' is empty", path_config);
        r = -1;
        goto close_fd;
    }
    if (lseek(fd_config, 0, SEEK_SET)) {
        println_error_with_errno("Failed to seek to start of config file '%s'", path_config);
        r = -1;
        goto close_fd;
    }
    if (size_file >= size_buffer) {
        buffer_heap = malloc(size_file + 1);
        if (!buffer_heap) {
            println_error_with_errno("Failed to allocate memory for buffer to read config file '%s'", path_config);
            r = -1;
            goto close_fd;
        }
        buffer = buffer_heap;
    } else {
        buffer = buffer_stack;
    }
    size_read = read(fd_config, buffer, size_file);
    if (size_read < 0) {
        println_error_with_errno("Failed to read content of config file '%s'", path_config);
        r = -1;
        goto free_heap;
    }
    if (size_read != size_file) {
        println_error("Read size (%ld) != expected size (%ld)", size_read, size_file);
        r = -1;
        goto free_heap;
    }
    buffer[size_file] = '\0';
    for (i = 0; i < size_read; ++i) {
        switch (buffer[i]) {
        case '[':
        case ']':
        case '\n':
        case '\0':
        case '=':
        }
    }
    r = 0;
free_heap:
    if (buffer_heap) free(buffer_heap);
close_fd:
    if (close(fd_config)) {
        println_error_with_errno("Failed to close fd for config file '%s'", path_config);
        r = -1;
    }
    return r;
}

int main() {




    return 0;
}