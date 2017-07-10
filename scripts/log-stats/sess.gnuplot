# style from http://youinfinitesnake.blogspot.com/2011/02/attractive-scientific-plots-with.html

set terminal pdfcairo font "Gill Sans,12" linewidth 4 rounded

set style line 80 lt rgb "#808080"

set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81
set border 3 back linestyle 80 # Remove border on top and right.  These
             # borders are useless and make it harder
             # to see plotted lines near the border.
    # Also, put it in grey; no need for so much emphasis on a border.
set xtics nomirror
set ytics nomirror

set style line 1 lt rgb "#A00000" lw 2 pt 1
set style line 2 lt rgb "#00A000" lw 2 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9


set output 'sessions.pdf'


set style data boxplot
#set boxwidth 0.5 absolute
#set style fill   solid 0.25 border lt -1
#unset key
#set style data boxplot
#set xtics border in scale 0,0 nomirror norotate  autojustify
#set xtics  norangelimit
#set xtics   ("A" 1.00000, "B" 2.00000)
#set ytics border in scale 1,0.5 nomirror norotate  autojustify
#set yrange [ 0.00000 : 1.000 ] noreverse nowriteback
#set xrange [ 0:30 ]
## Last datafile plotted: "silver.dat"
set xlabel 'Session length (seconds)'
set ylabel 'CDF'
set yrange [0:1]
set xrange [.1:10000]
set logscale x

plot './data/session-12.out.len.cdf' using 1:2 with lines title 'May 12',\
   './data/session-13.out.len.cdf' using 1:2 with lines title 'May 13',\
   './data/session-14.out.len.cdf' using 1:2 with lines title 'May 14',\
   './data/session-15.out.len.cdf' using 1:2 with lines title 'May 15',\
   './data/session-16.out.len.cdf' using 1:2 with lines title 'May 16',\
   './data/session-17.out.len.cdf' using 1:2 with lines title 'May 17'


set output 'num-sessions.pdf'
set xlabel 'Number of sessions'
plot './data/session-12.out.streams.cdf' using 1:2 with lines title 'May 12',\
   './data/session-13.out.streams.cdf' using 1:2 with lines title 'May 13',\
   './data/session-14.out.streams.cdf' using 1:2 with lines title 'May 14',\
   './data/session-15.out.streams.cdf' using 1:2 with lines title 'May 15',\
   './data/session-16.out.streams.cdf' using 1:2 with lines title 'May 16',\
   './data/session-17.out.streams.cdf' using 1:2 with lines title 'May 17'

set output 'max-download.pdf'
set xlabel 'Max download stream per session'
set xrange[1:1000000]
plot './data/session-12.out.maxd.cdf' using 1:2 with lines title 'May 12',\
   './data/session-13.out.maxd.cdf' using 1:2 with lines title 'May 13',\
   './data/session-14.out.maxd.cdf' using 1:2 with lines title 'May 14',\
   './data/session-15.out.maxd.cdf' using 1:2 with lines title 'May 15',\
   './data/session-16.out.maxd.cdf' using 1:2 with lines title 'May 16',\
   './data/session-17.out.maxd.cdf' using 1:2 with lines title 'May 17'

set output 'recon-time.pdf'
set xlabel 'Reconnect time'
set xrange [.1:100]
#unset logscale x
plot './data/session-12.out.recon.cdf' using 1:2 with lines title 'May 12',\
   './data/session-13.out.recon.cdf' using 1:2 with lines title 'May 13',\
   './data/session-14.out.recon.cdf' using 1:2 with lines title 'May 14',\
   './data/session-15.out.recon.cdf' using 1:2 with lines title 'May 15',\
   './data/session-16.out.recon.cdf' using 1:2 with lines title 'May 16',\
   './data/session-17.out.recon.cdf' using 1:2 with lines title 'May 17'

