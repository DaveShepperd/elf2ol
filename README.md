# elf2zo:

This application was written in the early 1990's. It was used to compress elf images produced by mainly mipsel-elf toolchains for the Midway Games systems.
The resulting image was included as data in a bootable EPROM which, at boot time, would decompress into memory an image selected via a DIP switch then
jump to appropriate memory location to continue the boot process.

# rdelf:

This application was written in the early 1990's. It was used to display the contents of an elf file. I didn't remember I had this or I might have written elf2ol differently.

# elf2ol:
This is probably a usless application. Written in late 2025.
I was chasing a very obscure bug in mac68k and thought I might be able to find it if I could convert the elf files produced by m68k-elf-gcc (and m68k-elf-as) into files that could be handled by llf (.ol format files.
I first coded this app to dump the elf files just to see if I had the elf file decoded properly. Then I added the conversion to .ol but left the dump stuff in so it could be turned on with a command line option.

I only ever built it with gnu tools on Ubuntu and have no plans to ever use it elsewhere.

P.S. It did help find the problem with mac68k which has subsequently been fixed.
