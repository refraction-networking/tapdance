#!/usr/bin/python

import sys
import time

START_TIME = time.mktime(time.strptime('Sun May 14 00:00:00 2017'))
END_TIME = time.mktime(time.strptime('Sun May 21 00:00:00 2017'))
ADJUST_TIME = 0

if len(sys.argv) > 1:
    ADJUST_TIME = int(sys.argv[1])*60*60

#May 26, 2017 17:25:04.079412

for line in sys.stdin:


    ts_mon, ts_day, ts_year, ts_time, rest = line.split(' ', 4)

    ts_sec, ts_usecs, = ts_time.split('.')
    ts = time.mktime(time.strptime(ts_mon + ' ' + ts_day + ' ' + ts_year + ' ' +  ts_sec, '%b %d, %Y %H:%M:%S')) + (float(ts_usecs)/1000000)

    #sp = line.split(' ', 1)

    #ts = sp[0]
    #ts = float(ts)

    ts_adjust = ts + ADJUST_TIME
    line = '%.06f %s' % (ts_adjust, rest)
    t = time.localtime(ts)
    if ts >= START_TIME and ts < END_TIME and (t.tm_hour < 5 or t.tm_hour > 7):
        sys.stdout.write(line)

##day = time.strftime('%d', time.localtime(ts))
#
#    if f is None or day != last_day:
#        if f is not None:
#            f.close()
#        f = open('./data/session-%s.out' % day, 'w')
#
#    f.write(line)
#    last_day = day
#


