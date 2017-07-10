#!/usr/bin/python

#May 17, 2017 14:10:36.094819 (Core 7) INFO: newsession 69b09097cad0105d2174d1a64c10e81e R.R.x.x:2428 -> R.R.R.R:443
#May 17, 2017 14:10:36.094832 (Core 7) INFO: newstream 69b09097cad0105d2174d1a64c10e81e R.R.x.x:2428 -> R.R.R.R:443
#May 17, 2017 14:10:36.095850 (Core 3) INFO: error a57be97086dfbb88df7ba19c93489a8b client_protocol
#May 17, 2017 14:10:36.095893 (Core 3) INFO: delstream a57be97086dfbb88df7ba19c93489a8b 333 81
#May 17, 2017 14:10:36.095928 (Core 3) INFO: duperror a57be97086dfbb88df7ba19c93489a8b client_stream
#May 17, 2017 14:10:36.095936 (Core 3) INFO: delsession a57be97086dfbb88df7ba19c93489a8b 0 79
#May 17, 2017 14:10:36.096265 (Core 9) INFO: newstream 23d9db2b3e8a16bf56fb3609c0e35acd R.R.x.x:13573 -> R.R.R.R:443



import sys
import time

BUCKET_SIZE = 5*60    # seconds


gen_times = {}  # ts_bucket => {gen => count}

last_bucket = None

for line in sys.stdin:
    try:

        ts_mon, ts_day, ts_year, ts_time, _, core_num, inf, stat = line.strip().split(' ', 7)

        ts_sec, ts_usecs, = ts_time.split('.')
        ts = time.mktime(time.strptime(ts_mon + ' ' + ts_day + ' ' + ts_year + ' ' +  ts_sec, '%b %d, %Y %H:%M:%S')) + (float(ts_usecs)/1000000)

        if stat.startswith('listgen'):
            _, conn_id, gen = stat.split(' ')
            gen = int(gen)

            bucket = int(ts / BUCKET_SIZE)
            if bucket not in gen_times:
                gen_times[bucket] = {} # {gen => count}

            if gen not in gen_times[bucket]:
                gen_times[bucket][gen] = 0

            gen_times[bucket][gen] += 1

    except:
        pass

# get columns
columns = set()
for bucket in gen_times.keys():
    for gen in gen_times[bucket].keys():
        columns.add(gen)

sys.stdout.write('time  ')
for c in columns:
    sys.stdout.write('%d  ' % c)

sys.stdout.write('\n')

for bucket in gen_times.keys():

    bin_time = bucket*BUCKET_SIZE
    sys.stdout.write('%d  ' % bin_time)
    for gen in columns:
        n = 0
        if gen in gen_times[bucket]:
            n = gen_times[bucket][gen]
        sys.stdout.write('%d  ' % n)

    sys.stdout.write('\n')
