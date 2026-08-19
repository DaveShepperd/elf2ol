DEFINES = -DEXTERNAL_PACKED_STRUCTS -DALIGNMENT=0 -DLINUX=2 -D_ISOC99_SOURCE
ELFLIB = /usr/include/libelf
INCS =  -I${ELFLIB}

#
# For Linux systems:
CFLAGS = $(INCS) $(DEFINES) -g -std=c99 -Wall -pedantic -ansi -m32
CPPFLAGS = $(INCS) $(DEFINES) -g -std=c++17 -Wall -ansi 
CC = gcc 
CPP = g++

#.slient:
	
%.o : %.c
	$(CC) $(CFLAGS) -c $<

%.o : %.cpp
	$(CPP) $(CPPFLAGS) -c $<

default: elf2ol rdelf

elf2ol: elf2ol.o lib_hexdump.o Makefile
	$(CPP) -o $@ elf2ol.o lib_hexdump.o -lelf

elf2ol.o: elf2ol.cpp formats.h Makefile
lib_hexdump.o: lib_hexdump.cpp lib_hexdump.h Makefile

rdelf.o : rdelf.c formats.h Makefile
rdelf: rdelf.o
	$(CC) $(CFLAGS) -o $@ $< -lelf

clean:
	rm -f *.o elf2ol rdelf 
