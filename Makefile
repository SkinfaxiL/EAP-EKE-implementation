CC = gcc
CC_FLAGS = -Wall -Wextra -g
CC_LIBS = -lcrypto -ldl -lgmp
WIN_LIB_LOC = -I/usr/include/openssl -L/usr/lib/ssl

TARGETS = client server

all: $(TARGETS)

$(TARGETS): % : %.o eap_eke.o validate.o util.o PNonce.o
	$(CC) $(CC_FLAGS) $^ -o $@ $(CC_LIBS)

%.o: %.c
	$(CC) $(CC_FLAGS) -c $<

clean:
	rm -rf *.o $(TARGETS)

