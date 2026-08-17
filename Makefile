HDR = $(wildcard *.h)
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
EXE = $(subst .o,,$(OBJ))

CC=gcc
CFLAGS=-Wall
LIBRESSL_INSTALL_DIR=/Users/0300093557/dev/portable/build-static

# For OpenSSL
#LIBRESSL_INSTALL_DIR=/Users/0300093557/dev/openssl/nak3-build
#LDFLAGS += -L$(LIBRESSL_INSTALL_DIR)/lib -lssl -lcrypto

CFLAGS  += -Wall -Werror -g -O2 -I$(LIBRESSL_INSTALL_DIR)/include -fsanitize=address,undefined
LDFLAGS += -L$(LIBRESSL_INSTALL_DIR)/lib -lssl -lcrypto -fsanitize=address,undefined

all: $(EXE) $(OBJ)

%:%.c
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf *.o *.dSYM
