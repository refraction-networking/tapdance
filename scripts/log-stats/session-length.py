#!/usr/bin/python

#May 17, 2017 14:10:36.094819 (Core 7) INFO: newsession 69b09097cad0105d2174d1a64c10e81e R.R.x.x:2428 -> R.R.R.R:443
#May 17, 2017 14:10:36.094832 (Core 7) INFO: newstream 69b09097cad0105d2174d1a64c10e81e R.R.x.x:2428 -> R.R.R.R:443
#May 17, 2017 14:10:36.095850 (Core 3) INFO: error a57be97086dfbb88df7ba19c93489a8b client_protocol
#May 17, 2017 14:10:36.095893 (Core 3) INFO: delstream a57be97086dfbb88df7ba19c93489a8b 333 81
#May 17, 2017 14:10:36.095928 (Core 3) INFO: duperror a57be97086dfbb88df7ba19c93489a8b client_stream
#May 17, 2017 14:10:36.095936 (Core 3) INFO: delsession a57be97086dfbb88df7ba19c93489a8b 0 79
#May 17, 2017 14:10:36.096265 (Core 9) INFO: newstream 23d9db2b3e8a16bf56fb3609c0e35acd R.R.x.x:13573 -> R.R.R.R:443



streams = {}   # conn_id => (is_open, last_time)
sessions = {}  # conn_id => (start_time, src, dst, num_streams, bytes_up, bytes_down, streams, errs)
                            # streams = [(ts, duration, bytes_up, bytes_down)]
                            # errs = [(durations)]


def get_reconnects(sess_streams):
    last = None
    out = []
    for t, dur, up, down in sess_streams:
        if last is not None:
            out.append(t - last)
        last = t + dur
    return out

import sys
import time

for line in sys.stdin:

    try:
        if not 'INFO:' in line:
            continue


        ts_mon, ts_day, ts_year, ts_time, _, core_num, inf, stat = line.strip().split(' ', 7)


        ts_sec, ts_usecs, = ts_time.split('.')
        ts = time.mktime(time.strptime(ts_mon + ' ' + ts_day + ' ' + ts_year + ' ' +  ts_sec, '%b %d, %Y %H:%M:%S')) + (float(ts_usecs)/1000000)

        if stat.startswith('newstream'):
            _, conn_id, src, _, dst = stat.split(' ')
            if conn_id in streams:
                is_open, last_time = streams[conn_id]
                if not(is_open):
                    print '%s %.03f reconnect' % (conn_id, ts - last_time)
                else:
                    print '%s %.03f was open????' % (conn_id, ts - last_time)

            streams[conn_id] = (True, ts)

        elif stat.startswith('delstream'):
            _, conn_id, down, up, = stat.split(' ')
            is_open = False
            if conn_id in streams:
                is_open, last_time = streams[conn_id]
                if is_open:
                    print '%s %.03f lived' % (conn_id, ts - last_time)
                else:
                    print '%s %.03f was closed????' % (conn_id, ts - last_time)
            streams[conn_id] = (False, ts)

            if conn_id in sessions and is_open:
                start_time, src, dst, num_streams, bytes_up, bytes_down, sess_streams, dups = sessions[conn_id]
                num_streams += 1
                bytes_up += int(up)
                bytes_down += int(down)
                sess_streams.append((last_time, (ts-last_time), up, down))
                sessions[conn_id] = (start_time, src, dst, num_streams, bytes_up, bytes_down, sess_streams, dups)




        elif stat.startswith('newsession'):
            _, conn_id, src, _, dst = stat.split(' ')
            if conn_id in sessions:
                start_time, old_src, old_dst, num_streams, bytes_up, bytes_down, sess_streams, dups = sessions[conn_id]

                if (old_src == src and old_dst == dst):
                    dups.append((ts - start_time))
                    sessions[conn_id] = (start_time, src, dst, num_streams, bytes_up, bytes_down, sess_streams, dups)
                else:
                    print 'Err: newsession %s (%s -> %s) already in sessions: %s' % (conn_id, src, dst, sessions[conn_id])

            else:
                sessions[conn_id] = (ts, src, dst, 0, 0, 0, [], [])
        elif stat.startswith('delsession'):
            _, conn_id, down, up = stat.split(' ')
            if conn_id in sessions:
                start_time, src, dst, num_streams, bytes_up, bytes_down, sess_streams, dups = sessions[conn_id]
                reconns = get_reconnects(sess_streams)
                print '%0.06f %s (%s -> %s) %0.03f alive %d streams %d %d u/d %d dup %d maxd/s %0.03f avgrec' % \
                        (ts, conn_id, src, dst, (ts-start_time), num_streams, bytes_up, bytes_down, len(dups), \
                        max([float(down)/dur for (t, dur, up, down) in sess_streams]), \
                        sum(reconns) / len(reconns))

    except Exception as e:
        print 'Line "%s" got exception %s' % (line, e)




