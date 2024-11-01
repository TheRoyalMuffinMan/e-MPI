EXECS = mpi_hello_world mpi_isend
MPICC ?= mpicc

all: ${EXECS}

%: %.c
	${MPICC} -o $@ $<

clean:
	rm -f ${EXECS}

.PHONY: all clean
