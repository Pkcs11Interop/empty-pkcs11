# Display exported symbols:
#  nm -D empty-pkcs11.so | grep ' T '

SRC_DIR=../../src

CC= gcc
ARCH_FLAGS= -m32
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -O2 -I$(SRC_DIR)
LIBNAME=empty-pkcs11-x86.so

all: empty-pkcs11.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,empty-pkcs11.version \
	empty-pkcs11.o
	strip --strip-all $(LIBNAME)

empty-pkcs11.o: $(SRC_DIR)/empty-pkcs11.c $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/empty-pkcs11.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so
