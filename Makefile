.silent:

elf2ol: elf2ol.o lib_hexdump.o Makefile
	g++ -o $@ -O2 elf2ol.o lib_hexdump.o -lelf

elf2ol.o: elf2ol.cpp formats.h Makefile
	g++ -c -O2 -Wall -ansi $<

lib_hexdump.o: lib_hexdump.cpp lib_hexdump.h Makefile
	g++ -c -O2 -Wall $<

clean:
	rm -f elf2ol elf2ol.o lib_hexdump.o
