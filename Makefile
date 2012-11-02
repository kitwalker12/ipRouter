OBJS = iprouter.o iprt.o lpm.o
EXES = iprouter
CC = gcc
CFLAGS = -Wall -g
lib = -lpthread -lm -lpcap

iprouter : iprouter.o iprt.o lpm.o
	${CC} ${CFLAGS} -o iprouter iprouter.o iprt.o lpm.o ${lib}

iprouter.o : iprouter.c
	${CC} ${CFLAGS} -c iprouter.c

lpm.o : lpm.c lpm.h
	${CC} ${CFLAGS} -c lpm.c

iprt.o : iprt.c iprt.h
	${CC} ${CFLAGS} -c iprt.c

.PHONY: clean cleanobj

clean:
	rm -f ${OBJS} ${EXES}

cleanobj:
	rm -f ${OBJS}
