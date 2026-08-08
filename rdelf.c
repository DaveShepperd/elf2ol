#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libelf.h>
#include <unistd.h>
#include "formats.h"

int main(int argc, char *argv[])
{
	Elf * elf,*arf;
	Elf32_Ehdr *ehdr;
	Elf_Scn *scn;
	Elf32_Phdr *phdr;
	Elf_Data *data;
	Elf_Cmd cmd;
	int filedes, ii, sects;
	unsigned char elfHeader[5];
	int sts;
	
	if ( argc < 2 )
	{
		printf("Usage: rdelf input\n");
		return 1;
	}
	--argc;
	++argv;
	filedes = open(*argv, O_RDONLY, 0664);
	if ( filedes < 0 )
	{
		perror("Unable to open output");
		return 3;
	}

	sts = read(filedes,elfHeader,sizeof(elfHeader));
	if ( sts != sizeof(elfHeader) )
	{
		perror("Failed to read input to determine 32/64 mode");
		close(filedes);
		return 4;
	}
	if ( elfHeader[4] != 1 )
	{
		if ( elfHeader[4] == 2 )
			printf("Input is elf64 format. This tool only handles elf32 input files.\n");
		else
			printf("Input is not elf32 format. Is type 0x%02X. This tool only handles elf32 input files.\n", elfHeader[4]);
		close(filedes);
		return 5;
	}
	if ( lseek(filedes, 0, SEEK_SET) != 0 )
	{
		perror("Failed to seek back to 0 after reading header");
		close(filedes);
		return 6;
	}
	elf_version(EV_CURRENT);
	if ( (arf = elf_begin(filedes, ELF_C_READ, (Elf *)0)) == 0 )
	{
		perror("elf_begin failed");
		return 4;
	}

	cmd = ELF_C_READ;
	while ( (elf = elf_begin(filedes, cmd, arf)) != 0 )
	{
		Elf32_Shdr * shdr,**sections;
		Elf_Data **section_data;
		char *sect_strings;
		if ( (ehdr = elf32_getehdr(elf)) != 0 )
		{
			printf("Elf header: ident class=%d, data=%d, ver=%d\n",
				   ehdr->e_ident[EI_CLASS], ehdr->e_ident[EI_DATA], ehdr->e_ident[EI_VERSION]);
			printf("   type = %d, machine = %d, version = %" FMT_L_PRFX "d, entry = %08" FMT_L_PRFX "X\n",
				   ehdr->e_type, ehdr->e_machine, ehdr->e_version, ehdr->e_entry);
			printf("   phoff = %" FMT_L_PRFX "d, shoff = %" FMT_L_PRFX "d, flags = %08" FMT_L_PRFX "X, ehsize = %d\n",
				   ehdr->e_phoff, ehdr->e_shoff, ehdr->e_flags, ehdr->e_ehsize);
			printf("   phentsize = %d, phnum = %d, shentsize = %d, shnum = %d\n",
				   ehdr->e_phentsize, ehdr->e_phnum, ehdr->e_shentsize, ehdr->e_shnum);
			printf("   shstrndx = %d\n", ehdr->e_shstrndx);
			if ( (phdr = elf32_getphdr(elf)) != 0 )
			{
				printf("Phdr: type=%" FMT_L_PRFX "d, off=%" FMT_L_PRFX "d, vaddr=%08" FMT_L_PRFX "X, paddr=%08" FMT_L_PRFX "X\n",
					   phdr->p_type, phdr->p_offset, phdr->p_vaddr, phdr->p_paddr);
				printf("   filsiz=%" FMT_L_PRFX "d, memsiz=%" FMT_L_PRFX"d, flags=%" FMT_L_PRFX "d, align=%" FMT_L_PRFX "d\n",
					   phdr->p_filesz, phdr->p_memsz, phdr->p_flags, phdr->p_align);
			}
			else
			{
				printf("No PHDR\n");
			}
			sections = (Elf32_Shdr **)calloc(ehdr->e_shnum, sizeof(Elf32_Shdr *));
			section_data = (Elf_Data **)calloc(ehdr->e_shnum, sizeof(Elf_Data *));
			for ( sects = ii = 0; ii < ehdr->e_shnum; ++ii )
			{
				if ( (scn = elf_getscn(elf, ii)) != 0 )
				{
					sections[ii] = elf32_getshdr(scn);
					section_data[ii] = elf_getdata(scn, 0);
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
					static const char *const type_names[] = {
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
						"Unknown",
						"Unknown",
						"Unknown",
						"Unknown",
						"Unknown",
						"Group"
					};
					if ( shdr->sh_type >= (Elf32_Word)n_elts(type_names) )
						type = "Unknown";
					else
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
				printf("   %2d, 0x%08" FMT_L_PRFX "X [%s] %s\n",
					   ii,
					   shdr->sh_type,
					   sect_strings ? sect_strings + shdr->sh_name : "",
					   type);
				printf("   name=%" FMT_L_PRFX "d, flags=%08" FMT_L_PRFX "X, addr=%08" FMT_L_PRFX "X, offset=%08" FMT_L_PRFX "X\n",
					   shdr->sh_name, shdr->sh_flags, shdr->sh_addr, shdr->sh_offset);
				printf("   size=%" FMT_L_PRFX "d, link=%" FMT_L_PRFX "d, info=%" FMT_L_PRFX "d, addralign=%" FMT_L_PRFX "d, entsize=%" FMT_L_PRFX "d\n",
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
						static const char Empty[] = "";
						const char *nm, *bindings, *types, *shndx;
						char shndxV[10];
						int bi, ti;
						
						if ( sym_strs )
							nm = sym_strs + sym->st_name;
						else
							nm = Empty;
						bi = ELF32_ST_BIND(sym->st_info);
						bindings = "<Unknown>";
						if ( bi == STB_LOCAL )
							bindings = "L"; /* "Local"; */
						else if ( bi == STB_GLOBAL )
							bindings = "G"; /* "Global"; */
						else if ( bi == STB_WEAK )
							bindings = "W"; /* "Weak"; */
						ti = ELF32_ST_TYPE(sym->st_info);
						types = "N"; /* "None"; */
						if ( ti == STT_OBJECT )
							types = "O"; /* "Object"; */
						else if ( ti == STT_FUNC )
							types = "F"; /* "Function"; */
						if ( sym->st_shndx == SHN_UNDEF )
							shndx = " *UND*";
						else if ( sym->st_shndx == SHN_ABS )
							shndx = " *ABS*";
						else if ( sym->st_shndx == SHN_COMMON )
							shndx = " *COM*";
						else if ( sym->st_shndx == SHN_XINDEX )
							shndx = " *IDX*";
						else
						{
							snprintf(shndxV,sizeof(shndxV),"0x%04X",sym->st_shndx);
							shndx = shndxV;
						}
						printf("   %4d: value=0x%08" FMT_L_PRFX "X, size=%7" FMT_L_PRFX "d, info=0x%02X(%s/%s), other=0x%02X, shndx=%s, [%s]\n",
							   jj,
							   sym->st_value,
							   sym->st_size,
							   sym->st_info,
							   bindings,
							   types,
							   sym->st_other,
							   shndx,
							   nm);
					}
				}
			}
			if ( !sects )
			{
				printf("No sections\n");
			}
		}
		cmd = elf_next(elf);
		elf_end(elf);
	}
	elf_end(arf);
	close(filedes);
	return 0;
}
