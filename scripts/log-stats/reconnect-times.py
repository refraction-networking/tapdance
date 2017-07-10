#!/usr/bin/python

#2017/24/04 19:12:04.801040 Core 1: newstream c624c57c2c6f54d31fa6bee2bf8c4400 R.R.x.x:20566 -> R.R.R.R:44
#2017/24/04 19:12:08.050562 Core 1: delstream c624c57c2c6f54d31fa6bee2bf8c4400 4145 2944
#2017/24/04 19:12:08.051156 Core 1: delsession c624c57c2c6f54d31fa6bee2bf8c4400 4040 2329


sessions = {}   # conn_id => (is_open, last_time)

import sys
import time

for line in sys.stdin:

    try:
        if 'STATUS' in line:
            # also this line has a backward %d/%m :(
            continue

        ts_day, ts_time, _, core_num, stat = line.split(' ', 4)


        ts_sec, ts_usecs, = ts_time.split('.')
        ts = time.mktime(time.strptime(ts_day + ' ' + ts_sec, '%Y/%d/%m %H:%M:%S')) + (float(ts_usecs)/1000000)

        if stat.startswith('newstream'):
            _, conn_id, src, _, dst = stat.split(' ')
            if conn_id in sessions:
                is_open, last_time = sessions[conn_id]
                if not(is_open):
                    print '%s %.03f reconnect' % (conn_id, ts - last_time)
                else:
                    print '%s %.03f was open????' % (conn_id, ts - last_time)

            sessions[conn_id] = (True, ts)

        elif stat.startswith('delstream'):
            _, conn_id, down, up, = stat.split(' ')
            if conn_id in sessions:
                is_open, last_time = sessions[conn_id]
                if is_open:
                    print '%s %.03f lived' % (conn_id, ts - last_time)
                else:
                    print '%s %.03f was closed????' % (conn_id, ts - last_time)
            sessions[conn_id] = (False, ts)
    except Exception as e:
        print 'Line "%s" got exception %s' % (line, e)

