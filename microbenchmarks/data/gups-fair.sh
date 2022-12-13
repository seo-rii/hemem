#!/usr/bin/gnuplot
set terminal pdf size 8,2 fontscale 0.7
set output "gups-fair.pdf"
#set xdata time
#set autoscale y
#file="/home/amanda/hemem-paper/figures/gups/hotset-move/mm-new.txt"
file1="data/fair/gups/be-gups.txt"
file2="data/fair/gups/second-gups.txt"
file3="data/fair/gups/third-gups.txt"
file4="data/fair/gups/fourth-gups.txt"
file5="data/fair/gups/fifth-gups.txt"
file6="data/fair/gups/sixth-gups.txt"
set datafile separator "\t"
#set xtics axis rangelimited
#set xtics scale 0.5 rotate by 25 offset -3,-0.5
#set arrow from 5, graph 0 to 5, graph 1 nohead
set ytics 0.01
#set key at 70, 0.024
#set key bottom right
set key outside top left horizontal font ",8"
set xrange [0:]
set yrange [0:0.05]

set xlabel "Time (s)"
set ylabel "GUPS"

cpu_freq=2100000000
start=`awk '{ if(min == 0) { min = $1 } else { min = $1 < min ? $1 : min } } END { print min }' data/fair/gups/*.txt`

#set title "GUPS Throughput"
plot \
  file1 using ($1-start)/cpu_freq:2 title "1.0 GUPS" with lines lw 4, \
	file2 using ($1-start)/cpu_freq:2 title "0.1 GUPS 1" with lines lw 4, \
	file3 using ($1-start)/cpu_freq:2 title "0.1 GUPS 2" with lines lw 4, \
	file4 using ($1-start)/cpu_freq:2 title "0.1 GUPS 3" with lines lw 4, \
	file5 using ($1-start)/cpu_freq:2 title "0.1 GUPS 4" with lines lw 4, \
  file6 using ($1-start)/cpu_freq:2 title "0.1 GUPS 5" with lines lw 4

