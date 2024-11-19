# e-MPI
eBPF for MPI with DVFS


- Nekbone
Just go to build example1 directory and use ./run.sh
1. data.rea can change iel0,ielN (512 => 1500)
2. Also change parameter (lelt=512) in SIZE file to maximum (1500 if you set 1500 in data.rea)
3. Only need to recompile if you change the SIZE file (remember in the makefile) pass this argument: -fallow-argument-mismatch in F77

- PENNANT
Just run Makefile and you should have a build directory, then you can run ./run.sh
1. If you want to vary the testing directory, you want to use .pnt files (maximum testing so far has been at sedovflatx4, don't go past this on on AMD system)
2. Can change tstop default (1.0 is very long run, 0.00001 is very fast run but not to completion)

- AMG
Just run ./run.sh, stick to problem 1 and don't go past -n 128 128 128 for AMD systems
1. Stick to all 12 cores being utilized