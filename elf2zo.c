#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libelf.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <zlib.h>
#include <sys/stat.h>
#include "formats.h"

#define NAMES_SHSTRTAB	".shstrtab"
#define NAMES_TEXT	".text"
#define NAMES_SYMTAB	".symtab"
#define SUFFIX_COMP	"_comp_size"		/* size of data compressed */
#define SUFFIX_DECOMP	"_decomp_size"		/* size of data uncompressed */
#define SUFFIX_XFER	"_xfer_addr"		/* transfer address */
#define NUM_SYMS	(6)			/* number of symbols in symbol table */

static const char *help_msg[] = {
	"Usage: elf2zo [-nsym_name] [-i] [-z] input output\n",
	"Where:\n",
	"   -e = make output file executable elf instead of relocatable\n",
	"   -i = input file is raw binary (image) instead of .elf\n",
	"   -n syn_name = ASCII string to become label of data\n",
	"        (name defaults to same as output filename if this\n",
	"        parameter is not specified; ignored if -e specified)\n",
	"   -v = set verbose (announce operations)\n",
	"   -z = DON\'T compress the data\n",
	"    input = input filename\n",
	"    output = output filename\n",
	0
};

static int say_help(void)
{
	int ii;
	for ( ii = 0; help_msg[ii]; ++ii )
	{
		fputs(help_msg[ii], stdout);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	Elf * elf,*arf;
	Elf32_Ehdr *ehdr;
	Elf_Scn *scn;
	Elf32_Shdr * shdr,**allsecs;
	Elf32_Phdr *phdr;
	Elf32_Sym *sym;
	Elf_Data * data,**allsecs_data;
	int filedes, image = 0, no_compress = 0, out_exe = 0, num_secs;
	char *u_sym_name = 0, *strings;
	int str_size;
	int sym_name_off = 0, sym_comp_off = 0, sym_decomp_off = 0, sym_xfer_off = 0;
	char *s = 0;
	const char *inpFileName, *outFileName;
	unsigned char *prog = 0;
	Elf32_Addr prog_len = 0;
	int len, sts, verbose = 0;
	Elf_Cmd cmd;
	Elf32_Addr prog_base=0, prog_memsz=0, prog_sa=0;
	uLong comprLen = 0, prog_align = 4;
	unsigned char *compr = 0;
	int opt;
	
	printf("elf2zo Copyright 1998 Atari Games, Corp. Version %s %s\n", __DATE__, __TIME__);
	elf_version(EV_CURRENT);        /* required by the elf library functions */
	while ( (opt=getopt(argc,argv,"ein:vz")) != -1 )
	{
		switch (opt)
		{
		case 'e':
			out_exe = 1;
			continue;
		case 'i':
			image = 1;
			continue;
		case 'n':
			u_sym_name = optarg;
			continue;
		case 'v':
			verbose = 1;
			continue;
		case 'z':
			no_compress = 1;
			continue;
		default:
			return say_help();
		}
	}
	if ( argc-optind < 2 )
	{
		return say_help();
	}
	inpFileName = argv[optind];
	outFileName = argv[optind+1];
	filedes = open(inpFileName, O_RDONLY, 0); /* open input file */
	if ( filedes < 0 )
	{
		perror("Unable to open input");
		return 2;
	}

	if ( !image )
	{
		unsigned char elfHeader[6];
		int sts;
		
		sts = read(filedes,elfHeader,sizeof(elfHeader));
		if ( sts != sizeof(elfHeader) )
		{
			perror("Failed to read input to determine 32/64 mode");
			close(filedes);
			return 3;
		}
		if ( elfHeader[EI_CLASS] != ELFCLASS32 )
		{
			static const char *endian;
			if ( elfHeader[EI_DATA] == ELFDATA2LSB )
				endian = "Little";
			else if ( elfHeader[EI_DATA] == ELFDATA2MSB )
				endian = "Big";
			else
				endian = "Unknown";
			if ( elfHeader[EI_CLASS] == ELFCLASS64 )
				printf("Input is elf64, %s endian format. This tool only handles input files of elf32.\n", endian);
			else
				printf("Input is not elf32, %s endian format. Is class: 0x%02X, data: 0x%02X. This tool only handles input files of elf32.\n",
					   endian, elfHeader[EI_CLASS], elfHeader[EI_DATA]);
			close(filedes);
			return 4;
		}
		if ( lseek(filedes, 0, SEEK_SET) != 0 )
		{
			perror("Failed to seek back to 0 after reading header");
			close(filedes);
			return 5;
		}
		elf_version(EV_CURRENT);
		if ( (arf = elf_begin(filedes, ELF_C_READ, (Elf *)0)) == 0 ) /* prepare to decode */
		{
			perror("elf_begin on input file failed");
			return 6;
		}

		cmd = ELF_C_READ;
		while ( (elf = elf_begin(filedes, cmd, arf)) != 0 )
		{
			char *sect_strings;
			ehdr = elf32_getehdr(elf);
			if ( ehdr != 0 && (phdr = elf32_getphdr(elf)) != 0 )    /* get program header */
			{
				int ii;
				for ( ii = 0; ii < ehdr->e_phnum; ++ii, ++phdr )
				{
					if ( phdr->p_filesz )
						break;          /* find the first one with a size */
				}
				if ( ii < ehdr->e_phnum && phdr->p_filesz )
				{
					int jj, sects;
					num_secs = ehdr->e_shnum;
					allsecs = (Elf32_Shdr **)calloc(num_secs, sizeof(Elf32_Shdr *));
					allsecs_data = (Elf_Data **)calloc(num_secs, sizeof(Elf_Data *));
					prog_base = 0xFFFFFFFF;
					prog_align = 0;
					prog_len = 0;
					prog_memsz = 0;
					for ( sects = jj = 0; jj < num_secs; ++jj )
					{
						if ( (scn = elf_getscn(elf, jj)) != 0 )
						{
							shdr = allsecs[jj] = elf32_getshdr(scn);
							allsecs_data[jj] = elf_getdata(scn, 0);
							++sects;
						}
					}
					if ( allsecs[ehdr->e_shstrndx]->sh_type == SHT_STRTAB )
					{
						sect_strings = (char *)allsecs_data[ehdr->e_shstrndx]->d_buf;
					}
					else
					{
						sect_strings = 0;
					}
					for ( jj = 0; jj < num_secs; ++jj )
					{
						shdr = allsecs[jj];
						if ( shdr && (shdr->sh_type == SHT_PROGBITS ||
									  shdr->sh_type == SHT_MIPS_REGINFO ||
									  shdr->sh_type == SHT_NOBITS) )
						{
							if ( sect_strings && !strcmp(".comment", sect_strings + shdr->sh_name) )
								continue;
							if ( (uLong)shdr->sh_addr < prog_base )
								prog_base = shdr->sh_addr;
							if ( shdr->sh_addralign > prog_align )
								prog_align = shdr->sh_addralign;
							if ( shdr->sh_type != SHT_NOBITS )
							{
								if ( shdr->sh_addr + shdr->sh_size > prog_len )
								{
									prog_len = shdr->sh_addr + shdr->sh_size;
								}
							}
							if ( shdr->sh_addr + shdr->sh_size > prog_memsz )
							{
								prog_memsz = shdr->sh_addr + shdr->sh_size;
							}
						}
					}
					prog_sa = ehdr->e_entry;        /* record starting address */
					prog_len = prog_len - prog_base;    /* data length is dif between start and end of PROGBITS */
					prog_memsz = prog_memsz - prog_base; /* memsize is diff between start and end of all sects */
					prog = (unsigned char *)calloc(prog_len, 1);     /* place to put uncompressed data */
					if ( verbose )
					{
						printf("Phdr: type=%" FMT_L_PRFX "d, off=%" FMT_L_PRFX "d, vaddr=%08" FMT_L_PRFX "X, paddr=%08" FMT_L_PRFX "X, saddr=%08" FMT_L_PRFX "X\n",
							   phdr->p_type, phdr->p_offset,
							   phdr->p_vaddr, phdr->p_paddr, prog_sa);
						printf("   filsiz=%" FMT_L_PRFX "d, memsiz=%" FMT_L_PRFX "d, flags=%" FMT_L_PRFX "d, align=%" FMT_L_PRFX "d\n",
							   phdr->p_filesz, phdr->p_memsz,
							   phdr->p_flags, phdr->p_align);
						printf("   prog_base=%08" FMT_L_PRFX "X, prog_len=%08" FMT_L_PRFX "X, prog_sa=%08" FMT_L_PRFX "X, prog_memsz=%08" FMT_L_PRFX "X\n",
							   prog_base, prog_len, prog_sa, prog_memsz);
					}
					if ( !prog )
					{
						fprintf(stderr, "Unable to malloc %d bytes\n", prog_len);
						return 7;
					}
					for ( jj = 0; jj < sects; ++jj )
					{
						shdr = allsecs[jj];
						if ( sect_strings && !strcmp(".comment", sect_strings + shdr->sh_name) )
							continue;
						if ( shdr && (shdr->sh_type == SHT_PROGBITS || shdr->sh_type == SHT_MIPS_REGINFO) )
						{
							uLong off;
							off = shdr->sh_addr - prog_base;
							data = allsecs_data[jj];
							if ( data )
							{
								if ( verbose )
								{
									Elf32_Word max, kk;
									unsigned char *sp = (unsigned char *)data->d_buf;
									
									printf("Loading %7" FMT_L_PRFX "d bytes to vaddr %08" FMT_L_PRFX "X (offset %08lX) from section %2d [%s]\n",
										   shdr->sh_size, shdr->sh_addr, off, jj,
										   sect_strings ? sect_strings + shdr->sh_name : "");
									max = 16;
									if ( max > shdr->sh_size )
										max = shdr->sh_size;
									printf("\t");
									for ( kk = 0; kk < max; ++kk )
									{
										printf("%02X ", *sp++);
									}
									printf("\n");
								}
								memcpy(prog + off, data->d_buf, shdr->sh_size);
							}
							else
							{
								fprintf(stderr, "No data in section %d [%s]\n",
										jj, sect_strings ? sect_strings + shdr->sh_name : "");
							}
						}
					}
				}
			}
			else
			{
				printf("No PHDR\n");
			}
			cmd = elf_next(elf);
			elf_end(elf);
			break;
		}
		elf_end(arf);
	}
	else
	{
		struct stat st;
		sts = fstat(filedes, &st);
		if ( sts < 0 )
		{
			perror("Error fstat'ing input file");
			return 9;
		}
		prog_len = st.st_size;
		if ( prog_len )
		{
			prog = (unsigned char *)malloc(prog_len);
			if ( !prog )
			{
				fprintf(stderr, "Unable to malloc %d bytes\n", prog_len);
				return 10;
			}
			sts = read(filedes, prog, prog_len);
			if ( (Elf32_Addr)sts != prog_len )
			{
				perror("Read error on input");
				return 11;
			}
		}
	}
	close(filedes);             /* done with this */

	if ( !prog_len )                /* if no program data */
	{
		printf("Input file empty\n");
		return 12;
	}
	if ( !no_compress )
	{
		comprLen = (prog_len * 11) / 10;        /* make buffer for compressed data 110% */
		compr = (unsigned char *)malloc(comprLen);
		sts = compress(compr, &comprLen, prog, prog_len); /* compress input data */
		if ( sts != Z_OK )
		{
			printf("Error compressing. Return code %d\n", sts);
			return 13;
		}
		if ( verbose )
			printf("Compressed %s from %d to %ld. Compression ratio %4.2f:1\n",
				   *argv, prog_len, comprLen, (float)prog_len / (float)comprLen);
	}
	++argv;                 /* advance to output filename */
	if ( !u_sym_name )              /* if no symbol name provided */
	{
		char *beg, *end;
		s = *argv;              /* point to output filename */
		beg = strrchr(s, '/');          /* remove leading '/'s */
		if ( !beg )
		{
			beg = s;
		}
		else
		{
			++beg;
		}
		end = strchr(beg, '.');         /* remove trailing '.'s */
		if ( !end )
			end = beg + strlen(beg);
		u_sym_name = (char *)malloc(end - beg + 1); /* get new space for string */
		strncpy(u_sym_name, beg, end - beg);  /* copy stripped string */
		u_sym_name[end - beg] = 0;        /* null terminated */
	}

/* Get buffer to hold all strings */
	len = strlen(u_sym_name);
	str_size = 1 + sizeof(NAMES_SHSTRTAB) + sizeof(NAMES_TEXT) + sizeof(NAMES_SYMTAB) +
		3 * (len + 1) + sizeof(SUFFIX_COMP) + sizeof(SUFFIX_DECOMP) + sizeof(SUFFIX_XFER);
	str_size = (str_size + 15) & -16;       /* round it up to 16 byte boundary */
	strings = (char *)malloc(str_size);
	strings[0] = 0;
/* Copy in all string names */
	memcpy(strings + 1, NAMES_SHSTRTAB, sizeof(NAMES_SHSTRTAB));
	memcpy(strings + 1 + sizeof(NAMES_SHSTRTAB), NAMES_TEXT, sizeof(NAMES_TEXT));
	memcpy(strings + 1 + sizeof(NAMES_SHSTRTAB) + sizeof(NAMES_TEXT), NAMES_SYMTAB, sizeof(NAMES_SYMTAB));

/* construct the _comp_size and _decomp_size strings */
	if ( !out_exe )
	{
		sym_name_off = 1 + sizeof(NAMES_SHSTRTAB) + sizeof(NAMES_TEXT) + sizeof(NAMES_SYMTAB);
		s = strings + sym_name_off;
		memcpy(s, u_sym_name, len + 1);
		sym_comp_off = sym_name_off + len + 1;
		s = strings + sym_comp_off;
		strcpy(s, u_sym_name);
		strcat(s, SUFFIX_COMP);
		sym_decomp_off = sym_comp_off + len + sizeof(SUFFIX_COMP);
		s = strings + sym_decomp_off;
		strcpy(s, u_sym_name);
		strcat(s, SUFFIX_DECOMP);
		sym_xfer_off = sym_decomp_off + len + sizeof(SUFFIX_DECOMP);
		s = strings + sym_xfer_off;
		strcpy(s, u_sym_name);
		strcat(s, SUFFIX_XFER);
	}

	filedes = open(outFileName, O_RDWR | O_TRUNC | O_CREAT, 0664);    /* open the output */
	if ( filedes < 0 )
	{
		perror("Unable to open output");
		return 14;
	}
	if ( (elf = elf_begin(filedes, ELF_C_WRITE, (Elf *)0)) == 0 ) /* prepare to write ELF file */
	{
		perror("elf_begin failed");
		return 15;
	}
	ehdr = elf32_newehdr(elf);      /* construct the elf header */
	ehdr->e_type = out_exe ? ET_EXEC : ET_REL;
	ehdr->e_machine = EM_MIPS;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_shstrndx = 1;
	ehdr->e_flags |= 0x20000000;
	ehdr->e_entry = prog_sa;

/* Construct the sections. */

	scn = elf_newscn(elf);      /* section 1 is the string table */
	shdr = elf32_getshdr(scn);
	shdr->sh_name = 1;          /* first name in the string table */
	shdr->sh_type = SHT_STRTAB;
	data = elf_newdata(scn);
	data->d_buf = strings;
	data->d_size = str_size;
	data->d_type = ELF_T_BYTE;

	scn = elf_newscn(elf);      /* section 2 is the .text section */
	shdr = elf32_getshdr(scn);
	shdr->sh_name = 1 + sizeof(NAMES_SHSTRTAB); /* second name in the string table */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC;
	if ( out_exe )
	{
		shdr->sh_addralign = 16;
		shdr->sh_flags |= SHF_EXECINSTR;
		shdr->sh_addr = prog_base;
		phdr = elf32_newphdr(elf, 1);
		if ( phdr )
		{
			phdr->p_type = PT_LOAD;
			phdr->p_vaddr = phdr->p_paddr = prog_base;
			phdr->p_memsz = prog_memsz;
			phdr->p_filesz = prog_len;
			phdr->p_align = prog_align;
			phdr->p_flags = 7;      /* rwx */
			phdr->p_offset = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) + str_size;
		}
	}
	data = elf_newdata(scn);
	if ( !no_compress )
	{
		data->d_buf = compr;
		data->d_size = comprLen;
	}
	else
	{
		data->d_buf = prog;
		data->d_size = prog_len;
	}
	data->d_type = ELF_T_BYTE;

	if ( !out_exe )
	{
		scn = elf_newscn(elf);      /* section 3 is the .symtab section */
		shdr = elf32_getshdr(scn);
		shdr->sh_name = 1 + sizeof(NAMES_SHSTRTAB) + sizeof(NAMES_TEXT); /* third name in string table */
		shdr->sh_type = SHT_SYMTAB;
		shdr->sh_flags = 0;
		shdr->sh_link = 1;          /* string table section index */
		shdr->sh_info = 2;          /* last local symbol index + 1 */
		data = elf_newdata(scn);
		data->d_buf = calloc(NUM_SYMS, sizeof(Elf32_Sym));
		data->d_size = (out_exe ? 2 : NUM_SYMS) * sizeof(Elf32_Sym);
		data->d_type = ELF_T_SYM;
		sym = (Elf32_Sym *)data->d_buf;

/* Construct the symbol table */
		++sym;              /* skip the 0th entry */
		sym->st_name = 0;       /* First entry is dummy local pointing to .text */
		sym->st_value = 0;      /* offset into section */
		sym->st_size = 0;       /* no size */
		sym->st_info = ELF32_ST_INFO(STB_LOCAL, STT_SECTION);
		sym->st_shndx = 2;      /* relative to section 2 */

		++sym;              /* Second entry is plain symbol */
		sym->st_name = sym_name_off;    /* offset to name string */
		sym->st_value = 0;      /* offset into section */
		sym->st_size = 0;       /* no size */
		sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_SECTION);
		sym->st_shndx = 2;      /* relative to section 2 (.text) */

		++sym;              /* Third entry is to 'symb'_comp_size; */
		sym->st_name = sym_comp_off;    /* offset to name string */
		sym->st_value = comprLen;   /* absolute value */
		sym->st_size = 0;       /* no size */
		sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
		sym->st_shndx = SHN_ABS;    /* ABS */

		++sym;              /* Fourth entry is to 'symb'_decomp_size */
		sym->st_name = sym_decomp_off;  /* offset to name string */
		sym->st_value = prog_len;   /* absolute value */
		sym->st_size = 0;       /* no size */
		sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
		sym->st_shndx = SHN_ABS;    /* ABS */

		++sym;              /* Fourth entry is to 'symb'_xfer_addr */
		sym->st_name = sym_xfer_off;    /* offset to name string */
		sym->st_value = prog_sa;    /* absolute value (start address) */
		sym->st_size = 0;       /* no size */
		sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
		sym->st_shndx = SHN_ABS;    /* ABS */
	}
	elf_update(elf, ELF_C_WRITE);   /* flush the output */
	elf_end(elf);
	close(filedes);
	free(prog);
	return 0;
}
