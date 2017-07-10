#!/bin/bash

len_gnuplot="plot "
streams_gnuplot="plot "
maxdl_gnuplot="plot "
recon_gnuplot="plot "

cat ~/.tapdance-prod/trial-week/rockymarmot-sessions.trial-week | \
        python bound-sessions.py > ./data/session-rockymarmot.out
cat ~/.tapdance-prod/trial-week/detroit-sessions.trail-week | \
        python bound-sessions.py > ./data/session-detroit.out
cat ~/.tapdance-prod/trial-week/windyegret-sessions.trail-week | \
        python bound-sessions.py > ./data/session-windyegret.out
#cat ~/.tapdance-prod/trial-week/windyheron-sessions.trail-week | \
cat ~/.tapdance-prod/trial-week/windyheron-sessions.trial-week | \
        python bound-sessions.py > ./data/session-windyheron.out

declare -A stations

stations["detroit"]="Station 1"
stations["windyheron"]="Station 2"
stations["windyegret"]="Station 3"
stations["rockymarmot"]="Station 4"


for fn in ./data/session-{detroit,windyheron,windyegret,rockymarmot}.out;
do
    cat $fn | awk '{print $6}' | sort -n | cdf > $fn.len.cdf
    cat $fn | awk '{print $8}' | sort -n | cdf > $fn.streams.cdf
    cat $fn | awk '{print $15}' | sort -n | cdf > $fn.maxd.cdf
    cat $fn | awk '{print $17}' | sort -n | cdf > $fn.recon.cdf

    name=`echo $fn | awk -F'.out' '{print $1}' | sed 's/session-//;s#./data/##'`
    id=`echo ${stations[$name]}`

    len_gnuplot+="'$fn.len.cdf' u 1:2 w lines title '$id', "
    streams_gnuplot+="'$fn.streams.cdf' u 1:2 w lines title '$id', "
    maxdl_gnuplot+="'$fn.maxd.cdf' u 1:2 w lines title '$id', "
    recon_gnuplot+="'$fn.recon.cdf' u 1:2 w lines title '$id', "
done

len_gnuplot=`echo -e $len_gnuplot`
streams_gnuplot=`echo -e $streams_gnuplot`
maxdl_gnuplot=`echo -e $maxdl_gnuplot`
recon_gnuplot=`echo -e $recon_gnuplot`

cat sess.gnuplot.template | sed "s#LEN_GNUPLOT#$len_gnuplot#" | \
        sed "s#STREAMS_GNUPLOT#$streams_gnuplot#" | \
        sed "s#MAXDL_GNUPLOT#$maxdl_gnuplot#" |\
        sed "s#RECON_GNUPLOT#$recon_gnuplot#" > sess2.gnuplot
