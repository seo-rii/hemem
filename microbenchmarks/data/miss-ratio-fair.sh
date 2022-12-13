#!/usr/bin/gnuplot
set terminal pdf size 8,2 fontscale 0.7
set output "miss-ratio-fair.pdf"
#set xdata time
#set autoscale y
file1="data/fair/logs/be-log.txt"
file2="data/fair/logs/second-log.txt"
file3="data/fair/logs/third-log.txt"
file4="data/fair/logs/fourth-log.txt"
file5="data/fair/logs/fifth-log.txt"
file6="data/fair/logs/sixth-log.txt"
set datafile separator "\t"
set ytics 0.2
set key outside top left horizontal font ",8"
set xrange [0:]
set yrange [0:1]

set xlabel "Time (s)"
set ylabel "Miss Ratio"

cpu_freq=2100000000
start=`awk '{ if(min == 0) { min = $1 } else { min = $1 < min ? $1 : min } } END { print min }' data/fair/logs/*.txt`

plot \
  file1 using ($1-start)/cpu_freq:2 title "1.0 GUPS" with lines lw 4, \
  file2 using ($1-start)/cpu_freq:2 title "0.1 GUPS 1" with lines lw 4, \
  file3 using ($1-start)/cpu_freq:2 title "0.1 GUPS 2" with lines lw 4, \
  file4 using ($1-start)/cpu_freq:2 title "0.1 GUPS 3" with lines lw 4, \
  file5 using ($1-start)/cpu_freq:2 title "0.1 GUPS 4" with lines lw 4, \
  file6 using ($1-start)/cpu_freq:2 title "0.1 GUPS 5" with lines lw 4

