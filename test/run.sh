#!/bin/bash

startEnergy=$(sudo /usr/local/bin/rdmsr 0x611) #intel 0x611, amd 0xc001029b
startTime_ms=$(date +%s%N | cut -b 1-13)

mpirun -np 52 --bind-to-core ./nekbone

endEnergy=$(sudo /usr/local/bin/rdmsr 0x611) #intel 0x611, amd 0xc001029b
endTime_ms=$(date +%s%N | cut -b 1-13)
totalEnergy=$((0x${endEnergy} - 0x${startEnergy}))
totalTime_ms=$((endTime_ms - startTime_ms))
totalTime_seconds=$(bc <<<"scale=2;$totalTime_ms/1000")
totalEnergy_joules=$(bc <<<"scale=2;$totalEnergy*61/1000000") #15.3 for amd, 61 for intel
averagePower=$(bc <<<"scale=2;$totalEnergy_joules/$totalTime_seconds")

echo "Total time (s): $totalTime_seconds" | tee -a result.txt
echo "Total energy (J): $totalEnergy_joules" | tee -a result.txt
echo "Average power (W): $averagePower" | tee -a result.txt
echo "" >> result.txt
