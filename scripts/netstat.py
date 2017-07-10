#!/usr/bin/python3
import subprocess
import time
import socket
import ssl

'''
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      1573/(squid-1)  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1355/sshd       
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      1609/master     
tcp        0      0 0.0.0.0:5666            0.0.0.0:*               LISTEN      1447/nrpe       
REDACTED BLOB  '''



# This isn't quite core ID, since we skip cores sometimes...
def get_core_affinity(pid):
    try:
        return int(open("/proc/{pid}/stat".format(pid=int(pid)), 'rb').read().split()[-14])
    except:
        return -1


test = False



hostname = socket.gethostname()

# Connect to stats server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tls_reporter = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1_2)
tls_reporter.connect(('REDACTED.edu', 443))

def report(core_num, stat_name, stat, t=None):
    global tls_reporter, hostname
    if t is None:
        t = int(time.time())
    try:
        s = 'tapdance.netstat.%s.%s.%s.count %s %d\n' % \
            (hostname, core_num, stat_name, stat, int(t))
        print(s)
        tls_reporter.sendall(bytes(s, 'ascii'))
    except Exception as e:
        print(e)
        # reconnect
        print('Reconnecting...')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_reporter = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, cert_reqs=ssl.CERT_NONE)
        try:
            tls_reporter.connect(('REDACTED.edu', 443))
        except:
            pass



def squid_cache_req(endpoint):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.2', 0))
    s.connect(('127.0.0.1', 1234))
    s.send(bytes('GET cache_object://localhost/%s HTTP/1.0\r\n\r\n' % endpoint, 'ascii'))
    buf = b''
    while True:
        d = s.recv(0xffff)
        if len(d) == 0:
            return buf
        buf += d


def get_squid_stats():
    global tls_reporter
    buf = squid_cache_req('info')
    cpu_use = 0.00
    cpu_use_agg = 0.00
    for line in buf.split(b'\n'):
        line = line.strip()
        if line.startswith(b'CPU Usage:'):
            cpu_use = float(line.split()[2].replace(b'%', b''))
            report('squid', 'cpu_use', ('%.2f' % cpu_use))
        elif line.startswith(b'CPU Usage, 5 minute avg:'):
            cpu_use_agg = float(line.split()[5].replace(b'%', b''))
            report('squid', 'cpu_use_5min', ('%.2f' % cpu_use_agg))


    parsing = False
    buf = squid_cache_req('client_list')
    for line in buf.split(b'\n'):
        line = line.strip()
        if line.startswith(b'Name:'):
            parsing = True
        elif parsing:
            if line.startswith(b'Currently established connections:'):
                curr_conns = int(line.split()[3])
                report('squid', 'cur_conns', '%d' % curr_conns)
            elif line.startswith(b'TAG_NONE'):
                report('squid', 'tag_none', '%d' % int(line.split()[1]))
            elif line.startswith(b'TCP_TUNNEL'):
                report('squid', 'tcp_tunnel', '%d' % int(line.split()[1]))
            elif line.startswith(b'TCP_MISS'):
                report('squid', 'tcp_miss', '%d' % int(line.split()[1]))
            elif line.startswith(b'TCP_DENIED'):
                report('squid', 'tcp_denied', '%d' % int(line.split()[1]))

    #print(buf)

while True:
    ns = subprocess.check_output(["netstat", "-pant"])

    if test:
        ns = open('test', 'rb').read()
        print('Test... %d' % len(ns))

    # Clear our memoize cache each time
    memoize_core_affinity = {}  #maps PID => core_num (via read /proc/$pid/stat)

    # Clear our stats
    # This dictionary tracks per tapdance process stats about all its connections:
    td_stats = {}  # core_num => [remote_recv_q_tot, remote_send_q_tot, remote_num_conns, <- clients
                    #             local_recv_q_tot, local_send_q_tot, local_num_conns]    <- squid

    # Init stats for squid
    td_stats['squid'] = [0]*6

    for line in ns.split(b'\n'):
        try:
            tcp, recv_q, send_q, local_addr, remote_addr, state, pid_prog = line.split()[:7]
            pid, prog = pid_prog.split(b'/', 2)
        except Exception as e:
            #print('Err: %s: %s' % (line, e))
            continue

        if state == b'ESTABLISHED':

            if b'squid' in prog:
                # Tracking squid connections
                if local_addr == b'127.0.0.1:1234':
                    # Local connection to TD
                    td_stats['squid'][3] += int(recv_q)
                    td_stats['squid'][4] += int(send_q)
                    td_stats['squid'][5] += 1
                else:
                    td_stats['squid'][0] += int(recv_q)
                    td_stats['squid'][1] += int(send_q)
                    td_stats['squid'][2] += 1

            elif prog == b'zc_tapdance':

                # Get PID => core num (approx*)
                if pid not in memoize_core_affinity:
                    memoize_core_affinity[pid] = get_core_affinity(pid)
                core_idx = memoize_core_affinity[pid]

                # Update stats
                if core_idx not in td_stats:
                    td_stats[core_idx] = [0]*6

                if remote_addr == b'127.0.0.1:1234':
                    # Local connection to squid
                    td_stats[core_idx][3] += int(recv_q)
                    td_stats[core_idx][4] += int(send_q)
                    td_stats[core_idx][5] += 1
                else:
                    # Remote connection
                    td_stats[core_idx][0] += int(recv_q)
                    td_stats[core_idx][1] += int(send_q)
                    td_stats[core_idx][2] += 1


    reconnect = False
    t = time.time()
    for core_idx in td_stats.keys():
        remote_recv_q_tot, remote_send_q_tot, remote_num_conns, \
            local_recv_q_tot, local_send_q_tot, local_num_conns = td_stats[core_idx]

        name = core_idx
        if name is not 'squid':
            name = 'Core %d' % core_idx
        print('%.3f % 8s: % 8d % 8d % 5d % 8d % 8d % 5d' % \
                (t, name, remote_recv_q_tot, remote_send_q_tot, remote_num_conns, \
                local_recv_q_tot, local_send_q_tot, local_num_conns))

        stats_names = ['remote_recv_q', 'remote_send_q', 'remote_num_conns',
                        'local_recv_q', 'local_send_q', 'local_num_conns']
        for i in range(len(stats_names)):
            report(core_idx, stats_names[i], ('%d' % td_stats[core_idx][i]), int(t))

    try:
        get_squid_stats()
    except Exception as e:
        print(e)
    time.sleep(1)

