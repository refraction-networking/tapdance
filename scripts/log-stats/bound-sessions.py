#!/usr/bin/python

import sys
import time

START_TIME = time.mktime(time.strptime('Sun May 14 00:00:00 2017'))
END_TIME = time.mktime(time.strptime('Sun May 21 00:00:00 2017'))
ADJUST_TIME = 0


for line in sys.stdin:
    sp = line.split(' ', 1)
    ts = sp[0]
    ts = float(ts)

    ts_adjust = ts + ADJUST_TIME
    line = '%.06f %s' % (ts_adjust, sp[1])
    if ts >= START_TIME and ts < END_TIME:
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


