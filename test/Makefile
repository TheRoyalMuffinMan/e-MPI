EXECS = mpi_hello_world 
MPICC ?= mpicc

all: ${EXECS}

%: %.c
	${MPICC} -o $@ $<

clean:
	rm -f ${EXECS}

.PHONY: all clean
