#define _GNU_SOURCE
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

// The Makefile in this directory provides a `make tapdance` and a
// `make zc_tapdance` rule. The latter causes the following #define to happen.
// `./scripts/tapdance-build.sh` ultimately calls `make zc_tapdance`, while
// `./scripts/tapdance-build.sh --nozerocopy` calls `make tapdance`.
// #define TAPDANCE_USE_PF_RING_ZERO_COPY
#ifdef TAPDANCE_USE_PF_RING_ZERO_COPY
#include "pfring_zc.h"
#define pfring_maybezc_stat pfring_zc_stat
#define pfring_maybezc_stats pfring_zc_stats
#else
#include "pfring.h"
#define pfring_maybezc_stat pfring_stat
#define pfring_maybezc_stats pfring_stats
#endif
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#include "rust_foreign_interface.h"

#include <loadkey.h>

// Provided by libtapdance
size_t write_reporter(uint8_t* buf, size_t len);

// NOTE / TODO:
// Once we are receiving filtered, 443-only traffic, we might need a lower
// PKT_BURST_SIZE! Although, given all of the non-443 junk that gets quickly
// discarded, maybe we could have a much larger burst size now, and the current
// burst size is appropriate for 443-only. We will have to experiment.
// Should probably keep PKT_BURST_SIZE a multiple of PF_BURST_SIZE.
#define PF_BURST_SIZE 16
#define PKT_BURST_SIZE 80
// When our last recv burst got nothing, we want to wait at least this long
// before doing another recv burst. If the Rust eloop tick doesn't take this
// long, do a sleep to make up the difference. (However, since minimum sleep is
// like 50us, the pause dur will overshoot. It's fine, though).
#define DESIRED_PAUSE_DUR_NS 10000

#define NO_ZC_BUFFER_LEN 9000
#define MAX_NUM_FORKED_PROCS 256
pid_t g_forked_pids[MAX_NUM_FORKED_PROCS];
#ifdef TAPDANCE_USE_PF_RING_ZERO_COPY
pfring_zc_queue* g_ring = 0;
pfring_zc_buffer_pool* g_pool = 0;
pfring_zc_pkt_buff* g_buf[PF_BURST_SIZE];
#else
pfring* g_ring = 0;
const char* g_iface_name = 0;
#endif
int g_num_worker_procs = 0;
void* g_rust_cli_conf_proto_ptr = 0;
void* g_rust_failed_map = 0;
int g_update_cli_conf_when_convenient = 0;
int g_update_overloaded_decoys_when_convenient = 0;

#define TIMESPEC_DIFF(a, b) ((a.tv_sec - b.tv_sec)*1000000000LL + \
                             ((int64_t)a.tv_nsec - (int64_t)b.tv_nsec))

void the_program(uint8_t core_id, unsigned int log_interval,
                 uint8_t* station_key)
{
    struct RustGlobalsStruct rust_globals = rust_init(core_id, station_key);
    g_rust_failed_map = rust_globals.fail_map;
    g_rust_cli_conf_proto_ptr = rust_globals.cli_conf;
    void* rust_ptr = rust_globals.global;

    rust_update_cli_conf(g_rust_cli_conf_proto_ptr);
#ifdef TAPDANCE_USE_PF_RING_ZERO_COPY
    printf("Zero-copy TapDance child proc started on core %d!\n", core_id);
#else
    printf("NON-zero-copy TapDance child proc started on core %d!\n", core_id);
    // For pfring_recv()s
    struct pfring_pkthdr hdr = {0};
    uint8_t* pkt_buf_ptr;
#endif
    int recvd_pkts = 0;

    // For Rust eloop tick and sleeping
    int64_t rust_dur_ns;
    struct timespec before_rust_events;
    struct timespec after_rust_events;
    // NOTE: 1ns sleeps are not possible. nanosleep(1) actually gives
    //       you sleeps of like mean 55.856us, stdev 6.851us.
    struct timespec minimum_sleep_dur;
    minimum_sleep_dur.tv_sec = 0;
    minimum_sleep_dur.tv_nsec = 1;

    // For rare (once per second) rust_periodic_cleanup() and packet drop check
    struct timespec prev_rust_drop;
    struct timespec prev_status_report;
    clock_gettime(CLOCK_MONOTONIC, &prev_rust_drop);
    clock_gettime(CLOCK_MONOTONIC, &prev_status_report);
    struct timespec cur_time_ns;
    int64_t ns_since_last_drop;
    int64_t ns_since_status_report;
    // log_interval is milliseconds
    int64_t log_interval_ns = log_interval * 1000LL * 1000LL;
    pfring_maybezc_stat stats;
    pfring_maybezc_stats(g_ring, &stats);
    unsigned long drops_prev = stats.drop;
    unsigned long drops_cur = stats.drop;

    while(1)
    {
        while(recvd_pkts < PKT_BURST_SIZE)
        {
#ifdef TAPDANCE_USE_PF_RING_ZERO_COPY
            int cur_recvd_pkts;
            if((cur_recvd_pkts =
                pfring_zc_recv_pkt_burst(g_ring, g_buf, PF_BURST_SIZE, 0)) > 0)
            {
                for(int i=0; i< cur_recvd_pkts; i++)
                {
                    rust_process_packet(
                        rust_ptr, pfring_zc_pkt_buff_data(g_buf[i], g_ring),
                        g_buf[i]->len);
                }
                recvd_pkts += cur_recvd_pkts;
            }
            else
                break;
#else
            if(pfring_recv(g_ring, &pkt_buf_ptr, 0, &hdr, 0) > 0)
                rust_process_packet(rust_ptr, pkt_buf_ptr, hdr.len);
            else
                break;
            recvd_pkts++;
#endif
        }

        clock_gettime(CLOCK_MONOTONIC, &before_rust_events);
        // 1 client doing some web browsing/youtube: mean 345.6ns, stdev 247.7ns
        // with no clients:                          mean 330.0ns, stdev 239.2ns
        rust_event_loop_tick(rust_ptr);
        clock_gettime(CLOCK_MONOTONIC, &after_rust_events);
        rust_dur_ns = TIMESPEC_DIFF(after_rust_events, before_rust_events);

        if(unlikely(recvd_pkts == 0 && rust_dur_ns < DESIRED_PAUSE_DUR_NS))
            nanosleep(&minimum_sleep_dur, 0);
        recvd_pkts = 0;

        clock_gettime(CLOCK_MONOTONIC, &cur_time_ns);
        ns_since_last_drop = TIMESPEC_DIFF(cur_time_ns, prev_rust_drop);
        ns_since_status_report = TIMESPEC_DIFF(cur_time_ns, prev_status_report);
        if(unlikely(ns_since_last_drop > 100LL*1000LL*1000LL)) // 100ms
        {
            prev_rust_drop = cur_time_ns;
            rust_periodic_cleanup(rust_ptr);
            if(unlikely(g_update_cli_conf_when_convenient))
            {
                g_update_cli_conf_when_convenient = 0;
                rust_update_cli_conf(g_rust_cli_conf_proto_ptr);
            }
            if(unlikely(g_update_overloaded_decoys_when_convenient))
            {
                g_update_overloaded_decoys_when_convenient = 0;
                rust_update_overloaded_decoys(rust_ptr);
            }
        }
        if(unlikely(ns_since_status_report > log_interval_ns))
        {
            prev_status_report = cur_time_ns;
            rust_periodic_report(rust_ptr);
            pfring_maybezc_stats(g_ring, &stats);
            drops_cur = stats.drop;

            // Always report to gobbler (prometheus philosophy)
            char buf[50]; // Enough for "drop x x\n" for x=2**64
            snprintf(buf, sizeof(buf), "drop %lu %lu\n",
                     (drops_cur - drops_prev), drops_cur);
            write_reporter((uint8_t*)buf, strlen(buf));

            drops_prev = drops_cur;
        }
    }
}

void ignore_sigpipe(int sig)
{
    printf("received a SIGPIPE, ignoring\n");
}

static void notify_cli_conf_file_update(int sig, siginfo_t* si, void* junk)
{
    g_update_cli_conf_when_convenient = 1;
}
static void notify_overloaded_decoys_file_update(int sig, siginfo_t* si,
                                                 void* junk)
{
    g_update_overloaded_decoys_when_convenient = 1;
}

void sigproc_child(int sig)
{
    static char called = 0;
    if(called) return; else called = 1;

#ifdef TAPDANCE_USE_PF_RING_ZERO_COPY
    pfring_zc_queue_breakloop(g_ring);
    for (int i=0; i<PF_BURST_SIZE; i++)
        pfring_zc_release_packet_handle_to_pool(g_pool, g_buf[i]);
    pfring_zc_ipc_detach_queue(g_ring);
    pfring_zc_ipc_detach_buffer_pool(g_pool);
    fprintf(stderr, "PF_RING zero-copy Tapdance child process shut down\n");
#else
    pfring_breakloop(g_ring);
    pfring_shutdown(g_ring);
    pfring_close(g_ring);
    fprintf(stderr, "PF_RING NON-zero-copy Tapdance child process shut down\n");
#endif
    exit(0);
}

void sigproc_parent(int sig)
{
    static char called = 0;
    if(called) return; else called = 1;

    fprintf(stderr, "PF_RING Tapdance shutting down...\n");

    int i, junk;
    for(i=0; i<g_num_worker_procs; i++)
        kill(g_forked_pids[i], SIGTERM);
    for(i=0; i<g_num_worker_procs; i++)
        waitpid(g_forked_pids[i], &junk, 0);
    fprintf(stderr, "PF_RING Tapdance done shutting down!\n");
    exit(0);
}

void set_affinity(int id)
{
    cpu_set_t cpuset;
    u_long core_id = id;
    int s;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)))
        fprintf(stderr, "Error binding to core %ld: errno=%i\n", core_id, s);
}

#ifdef TAPDANCE_USE_PF_RING_ZERO_COPY
void startup_pfring_maybezc(unsigned int cluster_id, int proc_ind)
{
    char cluster_iface_id[200];
    sprintf(cluster_iface_id, "zc:%d@%d", cluster_id, proc_ind);
    if(!(g_ring = pfring_zc_ipc_attach_queue(cluster_id, proc_ind, rx_only)))
    {
        fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] opening %s "
                        "(%d, %d)\n",
                strerror(errno), cluster_iface_id, cluster_id, proc_ind);
        exit(-1);
    }

    if(!(g_pool = pfring_zc_ipc_attach_buffer_pool(cluster_id, proc_ind)))
    {
        fprintf(stderr,
                "pfring_zc_ipc_attach_buffer_pool error [%s] opening %s\n",
                strerror(errno), cluster_iface_id);
        exit(-1);
    }

    for (int i=0; i<PF_BURST_SIZE; i++)
    {
        if(!(g_buf[i] = pfring_zc_get_packet_handle_from_pool(g_pool)))
        {
            fprintf(stderr,
                    "pfring_zc_get_packet_handle_from_pool error [%s] "
                    "opening %s\n", strerror(errno), cluster_iface_id);
            exit(-1);
        }
    }
}
#else
void startup_pfring_maybezc(unsigned int cluster_id, int proc_ind)
{
    char cluster_iface_id[200];
    memset(cluster_iface_id, 0, 200);
    if(g_iface_name)
        strncpy(cluster_iface_id, g_iface_name, 199);
    else
    {
        fprintf(stderr, "Not in ZC mode, but g_iface_name is null!\n");
        exit(-1);
    }
    if(!(g_ring = pfring_open(cluster_iface_id, 65535, PF_RING_PROMISC)))
    {
        fprintf(stderr, "pfring_open error [%s] opening %s in child %d\n",
                strerror(errno), cluster_iface_id, proc_ind);
        exit(-1);
    }
    if(pfring_set_cluster(g_ring, cluster_id, cluster_per_flow_2_tuple) < 0)
    {
        fprintf(stderr, "(non zero-copy) failed to set cluster id\n");
        exit(-1);
    }
    pfring_set_direction(g_ring, rx_only_direction);
    pfring_set_socket_mode(g_ring, recv_only_mode);
    if(pfring_enable_ring(g_ring) != 0)
    {
        pfring_close(g_ring);
        fprintf(stderr, "Error: pfring_enable_ring\n");
        exit(-1);
    }
}
#endif // TAPDANCE_USE_PF_RING_ZERO_COPY

pid_t start_tapdance_process(int core_affinity, unsigned int cluster_id,
                             int proc_ind, unsigned int log_interval,
                             uint8_t* station_key)
{
    pid_t the_pid = fork();
    if(the_pid == 0)
    {
        startup_pfring_maybezc(cluster_id, proc_ind);
        printf("Child proc %d created\n", core_affinity);

        set_affinity(core_affinity);
        signal(SIGINT, sigproc_child);
        signal(SIGTERM, sigproc_child);
        signal(SIGPIPE, ignore_sigpipe);
        the_program(proc_ind, log_interval, station_key);
        // (...the_program() runs until program termination))
    }
    printf("Core %d: PID %d, lcore %d\n", proc_ind, the_pid, core_affinity);
    return the_pid;
}

struct cmd_options
{
    // Number of cores to spread across.
    uint8_t         cpu_procs;

    // An integer that works as a handle to a PF_RING "cluster". These don't
    // need to be allocated or whatever; just pick one to pass as the -c arg to
    // zbalance_ipc, and pass the same one as the -c of this program. Can be
    // 1, 99, probably whatever.
    unsigned int    cluster_id;

    // Instead of starting at core 0 to core $cpu_procs, we'll do core
    // $core_affinity_offset to core $core_affinity_offset+$cpu_procs.
    // This allows us to run debug/production pf_rings on different cores
    // entirely (which rust likes), and with different cluster_ids.
    uint8_t         core_affinity_offset;

    // In seconds, interval between logging of bandwidth, tag checks/s, etc.
    unsigned int    log_interval;
    uint8_t*        station_key;  // the station key
    uint8_t*        public_key;   // the public key, used only for diagnostic
                                  // (all nuls if not provided)
    int             skip_core;    // -1 if not skipping any core, otherwise the core to skip
};

static uint8_t station_key[TD_KEYLEN_BYTES] = {
    224, 192, 103, 26, 96, 135, 130, 174,
    250, 208, 30, 113, 46, 128, 127, 111,
    215, 199, 5, 141, 38, 124, 34, 127,
    102, 142, 245, 81, 49, 70, 119, 119
};

static uint8_t public_key[TD_KEYLEN_BYTES] = { 0 };

void parse_cmd_args(int argc, char* argv[], struct cmd_options* options)
{
    // Defaults, development
    int32_t cpu_procs_i32 = 1; // struct member is a u8! catch overflow!
    options->cluster_id = 987654321;
    options->core_affinity_offset = 0;
    options->log_interval = 1000; // milliseconds
    int skip_core = -1; // If >0, skip this core when incrementing

    char* keyfile_name = 0;

    options->station_key = station_key;
    options->public_key = public_key;

    char c;
    while ((c = getopt(argc,argv,"i:n:c:o:l:K:s:")) != -1)
    {
        switch (c)
        {
            case 'i':
#ifdef TAPDANCE_USE_PF_RING_ZERO_COPY
                fprintf(stderr, "Warning: -i unused in zero copy mode\n");
#else
                g_iface_name = optarg;
#endif
                break;
            case 'n':
                cpu_procs_i32 = atoi(optarg);
                break;
            case 'c':
                options->cluster_id = atoi(optarg);
                break;
            case 'o':
                options->core_affinity_offset = atoi(optarg);
                break;
            case 'l':
                options->log_interval = 1000*atoi(optarg);
                break;
            case 'K':
                keyfile_name = optarg;
                break;
            case 's':
                skip_core = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Unknown option %c\n", c);
                break;
        }
    }
    if (options->cluster_id == 987654321)
    {
        fprintf(stderr, "Error: required -c cluster_id\n");
        exit(-1);
    }

    if (keyfile_name != NULL)
    {
        int rc = td_load_station_key(keyfile_name, options->station_key,
                                     options->public_key);
        if (rc != 0)
        {
            fprintf(stderr, "Error: can't load keyfile [%s]: %d\n",
                    keyfile_name, rc);
            exit(-1);
        }
        else
        {
            printf("Using public key: ");
            td_print_key(options->public_key);
            printf("\n");
        }
    }
    else
    {
        printf("Using default key\n");
    }

    int last_core_id_requested = (options->core_affinity_offset +
                                 cpu_procs_i32) - 1;
    if (skip_core > 0) last_core_id_requested++;
    if (last_core_id_requested >= MAX_NUM_FORKED_PROCS)
    {
        fprintf(stderr,
            "Error: highest requested core ID %d is too high of a core ID to\n"
            "ask for. This program can only use 0 through %d inclusive (even\n"
            "if your machine has more).\n",
            last_core_id_requested, MAX_NUM_FORKED_PROCS-1);
        if(options->core_affinity_offset != 0)
        {
            fprintf(stderr, "Hint: you specified a non-zero core offset (-o).\n"
                            "Try again without that argument.\n");
        }
        exit(-1);
    }
    int cores_online = get_nprocs_conf();
    if(last_core_id_requested >= cores_online)
    {
        fprintf(stderr,
            "Error: highest requested core ID %d is beyond the range of core\n"
            "IDs currently available on this machine. Cores 0 to %d inclusive\n"
            "are available.\n", last_core_id_requested, cores_online - 1);
        if(options->core_affinity_offset != 0)
        {
            fprintf(stderr, "Hint: you specified a non-zero core offset (-o).\n"
                            "Try again without that argument.\n");
        }
        exit(-1);
    }
#ifndef TAPDANCE_USE_PF_RING_ZERO_COPY
    if(g_iface_name == 0)
    {
        fprintf(stderr, "Error: you are running in non-zero-copy mode and did\n"
                        "       not specify a network interface with -i.\n");
        exit(-1);
    }
#endif
    options->cpu_procs = cpu_procs_i32;
    options->skip_core = skip_core;
}

int main(int argc, char* argv[])
{
    struct cmd_options options;
    parse_cmd_args(argc, argv, &options);

    g_num_worker_procs = options.cpu_procs;

    // To keep it simple, we will let the parent and children all have this same
    // handler. All the handler does is set a global flag to 1, so no big deal.
    struct sigaction sa1;
    sa1.sa_flags = SA_SIGINFO; // use sa_sigaction, not sa_handler
    sigemptyset(&sa1.sa_mask);
    sa1.sa_sigaction = notify_cli_conf_file_update;
    // Using sigaction() rather than signal() here because handlers registered
    // by sigaction() are persistent, whereas signal() requires a (hacky, racy)
    // rereg at the start of the handler.
    sigaction(SIGUSR1, &sa1, NULL);

    struct sigaction sa2;
    sa2.sa_flags = SA_SIGINFO; // use sa_sigaction, not sa_handler
    sigemptyset(&sa2.sa_mask);
    sa2.sa_sigaction = notify_overloaded_decoys_file_update;
    sigaction(SIGUSR2, &sa2, NULL);

    int i;
    int core_num = options.core_affinity_offset;
    for (i=0; i<g_num_worker_procs; i++)
    {
        printf("Starting process %d...\n", i);

        if (core_num == options.skip_core) core_num++;
        g_forked_pids[i] =
            start_tapdance_process(core_num,
                                   options.cluster_id, i, options.log_interval,
                                   options.station_key);
        core_num++;
    }
    signal(SIGINT, sigproc_parent);
    signal(SIGTERM, sigproc_parent);

    int wait_status = 0, wait_ret = 0, wait_errno = 0;
    for(i=0; i<g_num_worker_procs; i++)
    {
        do
        {
            wait_ret = waitpid(g_forked_pids[i], &wait_status, 0);
            wait_errno = errno;
            if (wait_ret == -1 && wait_errno != EINTR)
                perror("waitpid");
        } while (wait_ret == -1 && wait_errno == EINTR);

        printf("child proc %d ", i);
        if (WIFEXITED(wait_status))
            printf("exited, status=%d\n", WEXITSTATUS(wait_status));
        else if (WIFSIGNALED(wait_status))
            printf("killed by signal %d\n", WTERMSIG(wait_status));
        else if (WIFSTOPPED(wait_status))
            printf("stopped by signal %d\n", WSTOPSIG(wait_status));
        else if (WIFCONTINUED(wait_status))
            printf("continued\n");
        else
            printf("...not sure what happened!\n");
    }
    sigproc_parent(SIGTERM);
    return 0;
}
