#!/bin/bash

while [ 1 ];
do
        recv=`netstat -tan | awk '{sum+=$2} END {print sum}'`
        send=`netstat -tan | awk '{sum+=$3} END {print sum}'`
        now=`date +"%b %d %H:%M:%S %Y"`
        echo $now $recv $send
        sleep 1
done

