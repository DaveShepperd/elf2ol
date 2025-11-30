This is probably a usless application.
I was chasing a very obscure bug in mac68k and thought I might be able to find it if I could convert the elf files produced by m68k-elf-gcc (and m68k-elf-as) into files that could be handled by llf (.ol format files.
I first coded this app to dump the elf files just to see if I had the elf file decoded properly. Then I added the conversion to .ol but left the dump stuff in so it could be turned on with a command line option.

I only ever built it with gnu tools on Ubuntu and have no plans to ever use it elsewhere.
