#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _LARGEFILE64_SOURCE
	#define _LARGEFILE64_SOURCE
#endif
#define _FILE_OFFSET_BITS (64)

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libelf.h>
#include <elf.h>
#include <unistd.h>
#include <time.h>

#include "formats.h"
#include "lib_hexdump.h"
#include "version.h"

static void dump_section(Hexdump *hd, int sectionNumb, const Elf_Data *ptr)
{
	printf("Section dump %d: type=%d, version=%d, size=%" FMT_SZ_PRFX "d, offset=%" FMT_LL_PRFX "d, align=%" FMT_SZ_PRFX "d\n",
		   sectionNumb,
		   ptr->d_type,
		   ptr->d_version,
		   ptr->d_size,
		   ptr->d_off,
		   ptr->d_align);
	hd->dumpIt("Data: ", (const uint8_t *)ptr->d_buf, ptr->d_size);
}

static int help_em(const char *errMsg, const char *title)
{
	if ( errMsg )
		fprintf(stderr,"%s\n", errMsg);
	fprintf(stderr, "Usage: %s [-t nsecs] [-n] name\n",
			title);
	return 1;
}

typedef struct
{
	Elf32_Shdr *elfSection;
	Elf_Data *elfData;
	int id;
} OurSection_t;

typedef struct
{
	Elf32_Sym *elfSym;
	int id;
} OurSymbol_t;

int main(int argc, char *argv[])
{
	Elf * elf,*arf;
	Elf32_Ehdr *ehdr;
	Elf_Scn *scn;
	Elf32_Phdr *phdr;
	Elf_Data *data;
	int filedes, ii, sects, any = 0;
	Elf_Cmd cmd;
	Hexdump hd(0, NULL);
	FILE *output;
	int outPutHdr=0, opt, verbose=0, dumpIt=0;
	char *cp, *inpName, *target=NULL;
	char *outputFilename=NULL;
	char errMsg[128];
	
	while ( (opt = getopt(argc, argv, "do:v")) != -1 )
	{
		switch (opt)
		{
		case 'd':
			dumpIt = 1;
			break;
		case 'o':
			outputFilename = optarg;
			break;
		case 'v':
			++verbose;
			break;
		default: /* '?' */
			fprintf(stderr,"Undefined option -%c (%d)\n", isprint(opt)?opt:'.', opt );
			return help_em(NULL, argv[0]);
		}
	}

	if ( optind >= argc )
		return help_em("No input provided", argv[0]);

	if ( !dumpIt && !outputFilename )
	{
		return help_em("No output name provided", argv[0]);
	}
	
	inpName = strdup(argv[optind]);
	filedes = open(inpName, O_RDONLY, 0664);
	if ( filedes < 0 )
	{
		perror("Unable to open output");
		return 3;
	}
	elf_version(EV_CURRENT);
	if ( (arf = elf_begin(filedes, ELF_C_READ, (Elf *)0)) == 0 )
	{
		perror("elf_begin failed");
		return 4;
	}
	if ( !dumpIt )
	{
		output = fopen(outputFilename, "w");
		if ( !output )
		{
			perror("Failed to open output");
			close(filedes);
			return 1;
		}
		target = outputFilename;
	}
	cmd = ELF_C_READ;
	while ( (elf = elf_begin(filedes, cmd, arf)) != 0 )
	{
		++any;
		if ( (ehdr = elf32_getehdr(elf)) != 0 )
		{
			Elf32_Shdr * shdr,**sections;
			Elf_Data **section_data;
			OurSection_t *ourSections;
			OurSymbol_t *ourSymbols;
			int localId;
			char *sect_strings;

			sections = NULL;
			section_data = NULL;
			ourSections = NULL;
			localId = 1;
			if ( ehdr->e_shnum )
			{
				sections = (Elf32_Shdr **)calloc(ehdr->e_shnum, sizeof(Elf32_Shdr *));
				section_data = (Elf_Data **)calloc(ehdr->e_shnum, sizeof(Elf_Data *));
				ourSections = (OurSection_t *)calloc(ehdr->e_shnum, sizeof(OurSection_t));
			}
			if ( dumpIt )
			{
				static const char *DataTypes[] =
				{
					"None",                     // 0
					"2's comp, little endian",  // 1
					"2's comp, big endian",     // 2
					"Num",                      // 3
				};
				++any;
				printf("Elf header: ident class=%d, data=%d(%s), ver=%d\n",
					   ehdr->e_ident[EI_CLASS],
					   ehdr->e_ident[EI_DATA],
					   (ehdr->e_ident[EI_DATA] >= 0 && ehdr->e_ident[EI_DATA] <= 3) ? DataTypes[ehdr->e_ident[EI_DATA]] : "Undefined",
					   ehdr->e_ident[EI_VERSION]);
				printf("   type = %" FMT_PRFX "d, machine = %" FMT_PRFX "d, version = %" FMT_PRFX "d, entry = %08" FMT_PRFX "X\n",
					   ehdr->e_type, ehdr->e_machine, ehdr->e_version, ehdr->e_entry);
				printf("   phoff = %" FMT_PRFX "d, shoff = %" FMT_PRFX "d, flags = %08" FMT_PRFX "X, ehsize = %" FMT_PRFX "d\n",
					   ehdr->e_phoff, ehdr->e_shoff, ehdr->e_flags, ehdr->e_ehsize);
				printf("   phentsize = %d, phnum = %d, shentsize = %d, shnum = %d\n",
					   ehdr->e_phentsize, ehdr->e_phnum, ehdr->e_shentsize, ehdr->e_shnum);
				printf("   shstrndx = %d\n", ehdr->e_shstrndx);
				if ( (phdr = elf32_getphdr(elf)) != 0 )
				{
					printf("Phdr: type=%" FMT_PRFX "d, off=%" FMT_PRFX "d, vaddr=%08" FMT_PRFX "X, paddr=%08" FMT_PRFX "X\n",
						   phdr->p_type, phdr->p_offset, phdr->p_vaddr, phdr->p_paddr);
					printf("   filsiz=%" FMT_PRFX "d, memsiz=%" FMT_PRFX "d, flags=%" FMT_PRFX "d, align=%" FMT_PRFX "d\n",
						   phdr->p_filesz, phdr->p_memsz, phdr->p_flags, phdr->p_align);
				}
				else
				{
					printf("No PHDR\n");
				}
				for ( sects = ii = 0; ii < ehdr->e_shnum; ++ii )
				{
					if ( (scn = elf_getscn(elf, ii)) != 0 )
					{
						sections[ii] = elf32_getshdr(scn);
						section_data[ii] = elf_getdata(scn, NULL);
						++sects;
					}
				}
				if ( sections[ehdr->e_shstrndx]->sh_type == SHT_STRTAB )
				{
					sect_strings = (char *)section_data[ehdr->e_shstrndx]->d_buf;
				}
				else
				{
					sect_strings = NULL;           /* assume failure */
				}
				if ( !sect_strings )
				{
					printf("No section string table\n");
				}
				printf("Sections:\n");
				for ( ii = 1; (shdr = sections[ii]) && ii < ehdr->e_shnum; ++ii )
				{
					const char *type;
	
					type = "Unknown type";
					if ( shdr->sh_type < SHT_NUM )
					{
						static const char *const type_names[SHT_NUM] = {
							"Unused",
							"Program",
							"Symbol table",
							"String table",
							"Relocation entries with addends",
							"Symbol hash table",
							"Dynamic linking information",
							"Notes",
							"BSS",
							"Relocation entries, no addends",
							"Reserved",
							"Dynamic linker symbol table",
							"Array of constructors",
							"Array of destructors",
							"Array of pre-constructors",
							"Section group",
							"Extended section indices",
							"RELR relative relocations"
						};
						type = type_names[shdr->sh_type];
					}
					else if ( shdr->sh_type >= SHT_LOPROC && shdr->sh_type < SHT_HIPROC )
					{
						switch (shdr->sh_type)
						{
						case SHT_MIPS_LIBLIST:
							type = "MIPS Shared objects used in link";
							break;
						case SHT_MIPS_CONFLICT:
							type = "MIPS Conflicting symbols";
							break;
						case SHT_MIPS_GPTAB:
							type = "MIPS Global data area sizes";
							break;
						case SHT_MIPS_UCODE:
							type = "Reserved for SGI/MIPS compilers";
							break;
						case SHT_MIPS_DEBUG:
							type = "MIPS ECOFF debugging information";
							break;
						case SHT_MIPS_REGINFO:
							type = "MIPS Register usage information";
							break;
						case SHT_MIPS_OPTIONS:
							type = "MIPS Miscellaneous options.";
							break;
						case SHT_MIPS_DWARF:
							type = "MIPS DWARF debugging information.";
							break;
						case SHT_MIPS_EVENTS:
							type = "MIPS Event section.";
							break;
						default:
							break;
						}
					}
					printf("   %2d, [%s] type=0x%" FMT_PRFX "X (%s)\n",
						   ii,
						   sect_strings ? sect_strings + shdr->sh_name : "",
						   shdr->sh_type, type);
					printf("   name=%" FMT_PRFX "d, flags=%08" FMT_PRFX "X, addr=%08" FMT_PRFX "X, offset=%08" FMT_PRFX "X\n",
						   shdr->sh_name, shdr->sh_flags, shdr->sh_addr, shdr->sh_offset);
					printf("   size=%" FMT_PRFX "d, link=%" FMT_PRFX "d, info=%" FMT_PRFX "d, addralign=%" FMT_PRFX "d, entsize=%" FMT_PRFX "d\n",
						   shdr->sh_size, shdr->sh_link, shdr->sh_info,
						   shdr->sh_addralign, shdr->sh_entsize);
					if ( shdr->sh_type == SHT_SYMTAB )
					{
						int jj, num;
						Elf32_Sym *sym;
						Elf32_Shdr *strhdr;
						char *sym_strs = 0;
	
						strhdr = sections[shdr->sh_link];
						if ( strhdr && strhdr->sh_type == SHT_STRTAB )
						{
							sym_strs = (char *)section_data[shdr->sh_link]->d_buf;
						}
						data = section_data[ii];    /* get section data */
						sym = (Elf32_Sym *)data->d_buf;
						num = data->d_size / sizeof(Elf32_Sym);
						for ( jj = 0; jj < num; ++jj, ++sym )
						{
							const char *nm;
							if ( sym_strs )
							{
								nm = sym_strs + sym->st_name;
							}
							else
							{
								nm = "";
							}
							printf("   %4d: value=%08" FMT_PRFX "X, size=%3" FMT_PRFX "d, info=0x%02" FMT_PRFX "X, other=0x%02" FMT_PRFX "X, shndx=%3" FMT_PRFX "d, [%s]\n",
								   jj, sym->st_value, sym->st_size,
								   sym->st_info, sym->st_other, sym->st_shndx, nm);
						}
					}
					else if ( section_data[ii] )
						dump_section(&hd, ii, section_data[ii]);
					else
						printf("Section %d has no data\n", ii);
				}
				if ( !sects )
				{
					printf("No sections\n");
				}
			}
			else
			{
				if ( !outPutHdr )
				{
					char cpu[64];
					char timeBuf[64];
					time_t now = time(NULL);
					struct tm *tmPtr;
					tmPtr = localtime(&now);
					if ( ehdr->e_machine == 2 )
						strncpy(cpu, "x86", sizeof(cpu));
					else if ( ehdr->e_machine == 4 )
						strncpy(cpu, "M68000", sizeof(cpu));
					else
						snprintf(cpu,sizeof(cpu),"Unknown (%d)", ehdr->e_machine);
					strftime(timeBuf, sizeof(timeBuf), "%F %T", tmPtr);
					fprintf(output, ".id \"translator\" \"elf2ol %s (%d bit)\"\n", VERSION, sizeof(void *)==(size_t)4 ? 32:64);
					fprintf(output, ".id \"mod\" \"%s\"\n", target);
					fprintf(output, ".id \"date\" \"%s\"\n", timeBuf);
					fprintf(output, ".id \"target\" \"%s\"\n", cpu);
					outPutHdr = 1;
				}
				for ( sects = ii = 0; ii < ehdr->e_shnum; ++ii )
				{
					if ( (scn = elf_getscn(elf, ii)) != 0 )
					{
						sections[ii] = elf32_getshdr(scn);
						section_data[ii] = elf_getdata(scn, NULL);
						++sects;
					}
				}
				if ( sections[ehdr->e_shstrndx]->sh_type == SHT_STRTAB )
				{
					sect_strings = (char *)section_data[ehdr->e_shstrndx]->d_buf;
				}
				else
				{
					sect_strings = NULL;           /* assume failure */
				}
				if ( !sect_strings )
				{
					fprintf(stderr, "No section string table\n");
				}
				// Fill the sections as appropriate
				for ( ii = 1; (shdr = sections[ii]) && ii < ehdr->e_shnum; ++ii )
				{
					const char *nm;
					if ( (shdr->sh_type == SHT_PROGBITS || shdr->sh_type == SHT_NOBITS) && (shdr->sh_flags&SHF_ALLOC) )
					{
						  // Program data (.text or other RO code sections )
						nm = sect_strings ? sect_strings + shdr->sh_name : "";
						if ( shdr->sh_type == SHT_PROGBITS && (shdr->sh_flags&SHF_WRITE) )
							fprintf(stderr,"Warning: Section %s is writable. Must be read-only\n", nm);
						ourSections[ii].elfSection = sections[ii];
						ourSections[ii].elfData = section_data[ii];
						ourSections[ii].id = localId;
						++localId;
						fprintf(output,".seg {%s}%%%d %d %d {%s%s}\n",
								nm,
								ourSections[ii].id,
								shdr->sh_addralign == 1 ? 0 : 1,
								shdr->sh_addralign == 1 ? 0 : 1,
								(shdr->sh_flags&SHF_WRITE) ? "" : "r",
								(shdr->sh_type == SHT_NOBITS) ? "" : "u"
								);
						fprintf(output,".len %%%d %d\n",
								ourSections[ii].id,
								shdr->sh_size);
						continue;
					}
					if ( shdr->sh_type == SHT_SYMTAB )
					{
						int jj, num;
						Elf32_Sym *sym;
						Elf32_Shdr *strhdr;
						char *sym_strs = 0;

						strhdr = sections[shdr->sh_link];
						if ( strhdr && strhdr->sh_type == SHT_STRTAB )
						{
							sym_strs = (char *)section_data[shdr->sh_link]->d_buf;
						}
						data = section_data[ii];    /* get section data */
						sym = (Elf32_Sym *)data->d_buf;
						num = data->d_size / sizeof(Elf32_Sym);
						ourSymbols = (OurSymbol_t *)calloc(num,sizeof(OurSymbol_t));
						for ( jj = 0; jj < num; ++jj, ++sym )
						{
							if ( ELF32_ST_BIND(sym->st_info) )
							{
								if ( sym_strs )
								{
									nm = sym_strs + sym->st_name;
								}
								else
								{
									nm = "";
								}
								ourSymbols[jj].elfSym = sym;
								ourSymbols[jj].id = localId;
								++localId;
								if ( ELF32_ST_TYPE(sym->st_info) && (sym->st_shndx > 0 && sym->st_shndx < ehdr->e_shnum) )
								{
									fprintf(output, ".defg {%s}%%%d %%%d %d +\n",
											nm,
											ourSymbols[jj].id,
											ourSections[sym->st_shndx].id,
											sym->st_value);
								}
								else
								{
									fprintf(output, ".ext {%s}%%%d\n",
											nm,
											ourSymbols[jj].id);
								}
							}
							continue;
//							printf("   %4d: value=%08" FMT_PRFX "X, size=%3" FMT_PRFX "d, info=%4" FMT_PRFX "d, other=%4" FMT_PRFX "d, shndx=%3" FMT_PRFX "d, [%s]\n",
//								   jj, sym->st_value, sym->st_size,
//								   sym->st_info, sym->st_other, sym->st_shndx, nm);
						}
					}
				}
				for ( ii=1; (shdr = sections[ii]) && ii < ehdr->e_shnum; ++ii )
				{
				}
			}
			if ( sections )
				free(sections);
			if ( section_data )
				free(section_data);
			if ( ourSections )
				free(ourSections);
		}
		cmd = elf_next(elf);
		elf_end(elf);
	}
	if ( output )
		fclose(output);
	elf_end(arf);
	close(filedes);
	printf("Completed with 'any'=%d\n", any);
	return 0;
}
