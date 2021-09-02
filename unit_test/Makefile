OBJECTS := sdls_ep_interop_test.o

CFLAGS = \
-I../fsw/public_inc/ \
-I../cfe/inc \
-I../../../osal/src/os/inc/

VPATH = ../fsw/src ../fsw/public_inc

.PHONY: clean

all : clean sdls_ep_interop_test lib_crypto.a

sdls_ep_interop : sdls_ep_interop_test.o
	gcc sdls_ep_interop_test.o -o sdls_ep_interop

lib_crypto.a : sdls_ep_interop_test.o
	ar -crsv $@ sdls_ep_interop_test.o

%.o : %.c
	cc -c $(CFLAGS) $< -o $@



clean :
	-rm $(OBJECTS) sdls_ep_interop_test lib_crypto.a