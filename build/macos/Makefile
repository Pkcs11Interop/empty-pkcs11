# Display exported symbols:
#  nm empty-pkcs11.dylib | grep ' T '

SRC_DIR=../../src

CC= gcc
ARCH_FLAGS= -m32
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -O2 -I$(SRC_DIR)
LIBNAME=empty-pkcs11-x86.dylib

all: empty-pkcs11.o
	$(CC) $(ARCH_FLAGS) -dynamiclib -o $(LIBNAME) \
	-Wl,-exported_symbols_list,empty-pkcs11.symbols \
	empty-pkcs11.o
	strip -x $(LIBNAME)

empty-pkcs11.o: $(SRC_DIR)/empty-pkcs11.c $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/empty-pkcs11.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.dylib
