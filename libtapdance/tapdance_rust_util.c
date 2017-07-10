#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

void get_cpu_time(int64_t* usr_secs, int64_t* usr_micros,
                  int64_t* sys_secs, int64_t* sys_micros)
{
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    *usr_secs = usage.ru_utime.tv_sec;
    *usr_micros = usage.ru_utime.tv_usec;
    *sys_secs = usage.ru_stime.tv_sec;
    *sys_micros = usage.ru_stime.tv_usec;
}

extern void* g_rust_cli_conf_proto_ptr;
const void* get_global_cli_conf()
{
    return g_rust_cli_conf_proto_ptr;
}

extern void* g_rust_failed_map;
void* get_mut_global_failure_map()
{
    return g_rust_failed_map;
}

uint64_t g_rust_cli_download_count = 0;
void add_to_global_cli_download_count(uint64_t input)
{
    g_rust_cli_download_count += input;
}
void reset_global_cli_download_count()
{
    g_rust_cli_download_count = 0;
}
uint64_t get_global_cli_download_count()
{
    return g_rust_cli_download_count;
}

int REPORTER_FD = -1;
char REPORTER_FNAME[128];

int try_open_reporter()
{
    REPORTER_FD = open(REPORTER_FNAME, O_RDWR | O_NONBLOCK);
    return REPORTER_FD;
}

void open_reporter(const char *fname)
{
    strncpy(REPORTER_FNAME, fname, 128);
    try_open_reporter();
}

size_t write_reporter(uint8_t *buf, size_t len)
{
    if (REPORTER_FD < 0 && try_open_reporter() < 0) {
        return 0;
    }
    ssize_t ret = write(REPORTER_FD, buf, len);
    return (ret > 0) ? ret : 0;
}
