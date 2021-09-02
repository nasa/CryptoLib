OBJECTS := itc_gcm128_test.o itc_cmac128_test.o itc_aes128_test.o itc_gcm128.o itc_cmac128.o itc_aes128.o

CFLAGS = \
-I../../fsw/public_inc/ \
-I../../cfe/inc \
-I../../../../osal/src/os/inc/

VPATH = ../../fsw/src ../../fsw/public_inc

.PHONY: clean

all : clean itc_aes128_test itc_gcm128_test itc_cmac128_test libitc_crypto.a

itc_aes128_test : itc_aes128.o itc_aes128_test.o
	gcc itc_aes128.o itc_aes128_test.o -o itc_aes128_test

itc_gcm128_test : itc_aes128.o itc_gcm128.o itc_gcm128_test.o
	gcc itc_aes128.o itc_gcm128.o itc_gcm128_test.o -o itc_gcm128_test

itc_cmac128_test : itc_aes128.o itc_cmac128.o itc_cmac128_test.o
	gcc itc_aes128.o itc_cmac128.o itc_cmac128_test.o -o itc_cmac128_test

libitc_crypto.a : itc_gcm128.o itc_cmac128.o itc_aes128.o
	ar -crsv $@ itc_gcm128.o itc_cmac128.o itc_aes128.o

%.o : %.c
	cc -c $(CFLAGS) $< -o $@



clean :
	-rm $(OBJECTS) itc_aes128_test itc_gcm128_test itc_cmac128_test libitc_crypto.a