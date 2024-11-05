#!/bin/bash
#intel 0x611, amd 0xc001029b
sudo /usr/local/bin/rdmsr 0x611 >> pkg

/usr/bin/time mpirun -np 52 --bind-to-core ./nekbone

sudo /usr/local/bin/rdmsr 0x611 >> pkg
