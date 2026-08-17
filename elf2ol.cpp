/*
    elf2ol - Generic program to either dump the contents of an elf file
    or convert the elf file to .ol format suitable for use by LLF.
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file elf2ol.cpp
 *
 * @author shepperd (11/29/2025)
 *
 */

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

typedef struct
{
	const Elf32_Shdr *elfSection;
	const Elf_Data *elfData;
	const char *sectionName;
	int localID;
} OurSection_t;

typedef struct
{
	const Elf32_Sym *elfSym;	/* pointer to elf symbol table entry */
	const char *symbolName;		/* pointer to ASCII name */
	const OurSection_t *sectionPtr;	/* If just a section */
	int localID;				/* our local ID */
} OurSymbol_t;

static void dump_section(Hexdump *hd, size_t limit, int sectionNumb, const Elf_Data *ptr)
{
	printf("Section dump %d: type=%d, version=%d, size=%" FMT_SZ_PRFX "d, offset=%" FMT_LL_PRFX "d, align=%" FMT_SZ_PRFX "d\n",
		   sectionNumb,
		   ptr->d_type,
		   ptr->d_version,
		   ptr->d_size,
		   ptr->d_off,
		   ptr->d_align);
	if ( !ptr->d_buf )
		printf("\td_buf is NULL despite d_size being %" FMT_SZ_PRFX "d\n", ptr->d_size);
	else
	{
		if ( limit && ptr->d_size > limit )
			printf("section data displpayed clipped by %" FMT_SZ_PRFX "d bytes\n", ptr->d_size-limit);
		else
			limit = ptr->d_size;
		hd->dumpIt("Data: ", (const uint8_t *)ptr->d_buf, limit);
	}
}

typedef struct
{
	const char *target;
	Elf *elf;
	Elf32_Ehdr *ehdr;
	Elf32_Shdr **sections;
	Elf_Data **section_data;
	OurSection_t *ourSections;
	Hexdump *hd;
	int remap;
	int verbose;
	int limit;
	int errors;
	int dumpCvt;
	int dump2Rom;
} ElfParams_t;

static void showIndividualSection(const ElfParams_t *params, const char *sect_strings, const char *title, const Elf32_Shdr *shdr)
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
			"Relocation entries, no addends", /* 9 */
			NULL, /* 10 */
			"Dynamic linker symbol table", /* 11*/
			NULL, /* 12 */
			NULL, /* 13 */
			"Array of constructors", /* 14 */
			"Array of destructors",
			"Array of pre-constructors",
			"Section group",
			"Extended section indices",
			"RELR relative relocations"
		};
		type = type_names[shdr->sh_type];
		if ( !type )
			type = "Reserved";
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
	printf("%s [%s] type=0x%" FMT_PRFX "X (%s)\n",
		   title,
		   sect_strings ? sect_strings + shdr->sh_name : "",
		   shdr->sh_type, type);
	printf("   name=%" FMT_PRFX "d, flags=%08" FMT_PRFX "X, addr=%08" FMT_PRFX "X, offset=%08" FMT_PRFX "X\n",
		   shdr->sh_name, shdr->sh_flags, shdr->sh_addr, shdr->sh_offset);
	printf("   size=%" FMT_PRFX "d, link=%" FMT_PRFX "d, info=%" FMT_PRFX "d, addralign=%" FMT_PRFX "d, entsize=%" FMT_PRFX "d\n",
		   shdr->sh_size, shdr->sh_link, shdr->sh_info,
		   shdr->sh_addralign, shdr->sh_entsize);
}

static void showIndividualSymbol(const ElfParams_t *params, const char *sym_strs, const char *title, const Elf32_Sym *sym)
{
	const char *nm, *bindings, *types, *shndx;
	char shndxV[10];
	int bi, ti;

	if ( sym_strs )
		nm = sym_strs + sym->st_name;
	else
		nm = "";
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
	else if ( ti == STT_SECTION )
		types = "S"; /* Section */
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
	printf("%s value=0x%08" FMT_PRFX "X, size=%3" FMT_PRFX "d, info=0x%02X(%d:%s/%d:%s), other=0x%02X, shndx=%s, [%s]\n",
		   title,
		   sym->st_value,
		   sym->st_size,
		   sym->st_info,
		   bi,
		   bindings,
		   ti,
		   types,
		   sym->st_other,
		   shndx,
		   nm);
}

static void showSections(ElfParams_t *params)
{
	Elf_Scn *scn;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	Elf_Data *data, *eptr;
	int ii, sects;
	char *sect_strings;
	static const char *DataTypes[] =
	{
		"None",                     // 0
		"2's comp, little endian",  // 1
		"2's comp, big endian",     // 2
		"Num",                      // 3
	};
	
	Elf *elf = params->elf;
	Elf32_Ehdr *ehdr = params->ehdr;
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
			params->sections[ii] = elf32_getshdr(scn);
			params->section_data[ii] = elf_getdata(scn, NULL);
			++sects;
		}
	}
	if ( params->sections[ehdr->e_shstrndx]->sh_type == SHT_STRTAB )
	{
		sect_strings = (char *)params->section_data[ehdr->e_shstrndx]->d_buf;
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
	for ( ii = 1; (shdr = params->sections[ii]) && ii < ehdr->e_shnum; ++ii )
	{
		char title[16];
		snprintf(title,sizeof(title),"   %2d", ii);
		showIndividualSection(params,sect_strings,title,shdr);
		if ( shdr->sh_type == SHT_SYMTAB )
		{
			int jj, num;
			Elf32_Sym *sym;
			Elf32_Shdr *strhdr;
			char *sym_strs = 0;

			strhdr = params->sections[shdr->sh_link];
			if ( strhdr && strhdr->sh_type == SHT_STRTAB )
			{
				sym_strs = (char *)params->section_data[shdr->sh_link]->d_buf;
			}
			data = params->section_data[ii];    /* get section data */
			sym = (Elf32_Sym *)data->d_buf;
			num = data->d_size / sizeof(Elf32_Sym);
			for ( jj = 0; jj < num; ++jj, ++sym )
			{
				char title[64];
				snprintf(title,sizeof(title),"   0x%04X:", jj);
				showIndividualSymbol(params,sym_strs,title,sym);
			}
		}
		else if ( (eptr=params->section_data[ii]) && eptr->d_buf && eptr->d_size )
		{
			int jj;
			if ( shdr->sh_type == SHT_REL )
			{
				Elf32_Rel *rptr, *endPtr;

				endPtr = (Elf32_Rel *)((uint8_t *)eptr->d_buf + eptr->d_size);
				rptr = (Elf32_Rel *)eptr->d_buf;
				for (jj=0; rptr < endPtr; ++jj, ++rptr )
				{
					printf("\t0x%02X: r_offset=0x%08X, r_info=0x%08X, symIdx=0x%06X, relTyp=0x%02X\n",
						   jj,
						   rptr->r_offset,
						   rptr->r_info,
						   ELF32_R_SYM(rptr->r_info),
						   ELF32_R_TYPE(rptr->r_info)
						   );
				}
			}
			else if ( shdr->sh_type == SHT_RELA )
			{
				Elf32_Rela *rptr, *endPtr;

				endPtr = (Elf32_Rela *)((uint8_t *)eptr->d_buf + eptr->d_size);
				rptr = (Elf32_Rela *)eptr->d_buf;
				for (jj=0; rptr < endPtr; ++jj, ++rptr )
				{
					printf("\t%3d: r_offset=0x%08X, r_info=0x%08X, r_addend=0x%08X, symIdx=0x%06X, relTyp=0x%02X\n",
						   jj,
						   rptr->r_offset,
						   rptr->r_info,
						   rptr->r_addend,
						   ELF32_R_SYM(rptr->r_info),
						   ELF32_R_TYPE(rptr->r_info)
						   );
				}
			}
			else
			{
				dump_section(params->hd, params->limit, ii, params->section_data[ii]);
			}
		}
		else
			printf("Section %d has no data\n", ii);
	}
	if ( !sects )
	{
		printf("No sections\n");
	}
}

static void showInRomFormat(ElfParams_t *params)
{
	Elf_Scn *scn;
	Elf32_Shdr *shdr;
	int ii, sects;
	Elf *elf = params->elf;
	Elf32_Ehdr *ehdr = params->ehdr;
	char timeStamp[64];
	struct tm *ourTime;
	time_t now;
	
	for ( sects = ii = 0; ii < ehdr->e_shnum; ++ii )
	{
		if ( (scn = elf_getscn(elf, ii)) != 0 )
		{
			params->sections[ii] = elf32_getshdr(scn);
			params->section_data[ii] = elf_getdata(scn, NULL);
			++sects;
		}
	}
	now = time(NULL);
	ourTime = localtime(&now);
	strftime(timeStamp,sizeof(timeStamp),"%c",ourTime);
	printf("; ROM/PROM data file created via elf2ol V%s %s\n\n", VERSION, timeStamp);
	printf("; File name = stdout\n\n");
	for ( ii = 1; (shdr = params->sections[ii]) && ii < ehdr->e_shnum; ++ii )
	{
		if ( (shdr->sh_type == SHT_PROGBITS || shdr->sh_type == SHT_NOBITS) && (shdr->sh_flags&SHF_ALLOC))
		{
			Elf_Data *ptr = params->section_data[ii];
			
			if ( ptr->d_size && ptr->d_buf )
			{
				size_t jj, kk;
				Elf32_Word addr;
				uint8_t *chPtr;
				size_t limit;
				
				limit = params->limit ? params->limit : 16;
				addr = shdr->sh_addr;
				chPtr = (uint8_t *)ptr->d_buf;
				for (jj=0; jj < ptr->d_size; )
				{
					size_t lineLen = limit;
					if ( lineLen > ptr->d_size-jj )
						lineLen = ptr->d_size-jj;
					if ( addr >= 0x10000 )
						printf("%X=%02X", addr, *chPtr);
					else
						printf("%04X=%02X", addr, *chPtr);
					++chPtr;
					for ( kk = 1; kk < lineLen; ++kk, ++chPtr )
						printf(",%02X", *chPtr);
					printf("\n");
					addr += kk;
					jj += kk;
				}
			}
		}
	}
}

#if 0
typedef enum
{
	R_MIPS_NONE = 0,
	R_MIPS_16,		/* 16 bits */
	R_MIPS_32,		/* 32 bits */
	R_MIPS_REL32,	/* PC relative 32 bits */
	R_MIPS_26,		/* 4 (branch and jal) */
	R_MIPS_HI16,	/* 5 (upper 16 bits) */
	R_MIPS_LO16,	/* 6 (lower 16 bits) */
	R_MIPS_GPREL16,	/* 7 (GP relative 16 bits) (register == _gp == r28) */
	R_MIPS_LITERAL,
	R_MIPS_GOT16,
	R_MIPS_PC16,
	R_MIPS_CALL16,
	R_MIPS_GPREL32,
	R_MIPS_max
} Mips_RelocTypes_t;
#endif

#if 0
typedef enum
{
	R_M68K_NONE = 0,
	R_M68K_32,		/* 32 bits */
	R_M68K_max
} M68k_RelocTypes_t;

typedef enum reloc_type
{
	R_386_NONE = 0,
	R_386_32,
	R_386_PC32,
	R_386_GOT32,
	R_386_PLT32,
	R_386_COPY,
	R_386_GLOB_DAT,
	R_386_JUMP_SLOT,
	R_386_RELATIVE,
	R_386_GOTOFF,
	R_386_GOTPC,
	R_386_max
} x386_RelocTypes_t;
#endif

typedef struct
{
	ElfParams_t *params;
	FILE *output;
	Elf32_Ehdr *ehdr;
	OurSection_t *ourSections;	/* pointer to all our sections */
	OurSection_t *secToRel;		/* pointer to section to which these RELs apply */
	Elf_Data **section_data;	/* pointer to pointer to all section data */
	OurSymbol_t *ourSymbols;	/* pointer to our list of symbols */
	int numSymbols;				/* number of symbols in the list */
	char *symStrs;				/* pointer to symbol strings */
	Elf32_Addr	r_offset;		/* Address to org to */
	Elf32_Word	r_info;			/* Relocation type and symbol index */
	Elf32_Sword	r_addend;		/* Addend */
	int gpLocalID;				/* local ID of _gp variable */
} OurElf_Rel_t;

static Elf32_Half getElfHalf(const Elf32_Ehdr *ehdr, const uint8_t *src)
{
	Elf32_Half half;
	if ( ehdr->e_ident[EI_DATA] == ELFDATA2LSB )
	{
		/* little endian */
		half = (src[1] << 8) | src[0];
	}
	else
	{
		/* big endian */
		half = (src[0] << 8) | src[1];
	}
	return half;
}

static Elf32_Word getElfWord(const Elf32_Ehdr *ehdr, const uint8_t *src)
{
	Elf32_Word word;
	if ( ehdr->e_ident[EI_DATA] == ELFDATA2LSB )
	{
		/* little endian */
		word = (src[3]<<24) | (src[2]<<16) | (src[1] << 8) | src[0];
	}
	else
	{
		/* big endian */
		word = (src[0]<<24) | (src[1]<<16) | (src[2] << 8) | src[3];
	}
	return word;
}

static void outputOrg(OurElf_Rel_t *orptr)
{
	fprintf(orptr->output, ".org %%%d %d\n",
			orptr->secToRel->localID,
			orptr->r_offset);
}

static void outputRel(OurElf_Rel_t *orptr, int localID, const char *tag)
{
	if ( orptr->r_addend )
	{
		fprintf(orptr->output, "%%%d %d +:%s\n",
				localID,
				orptr->r_addend,
				tag
				);
	}
	else
	{
		fprintf(orptr->output, "%%%d:%s\n",
				localID,
				tag
				);
	}
}

static void outputRelExpr(OurElf_Rel_t *orptr)
{
	int relSymIdx = ELF32_R_SYM(orptr->r_info);
	int relRelType = ELF32_R_TYPE(orptr->r_info);
	int symType;
	int symLocalID;
	const char *tag;
	OurSection_t *segPtr;
	OurSymbol_t *symPtr;
	const Elf32_Sym *elfSym;
	
	if ( relSymIdx <= 0 || relSymIdx >= orptr->numSymbols )
	{
		fprintf(stderr, "Symbol index of %d (0x%X) is out of range. Can only be 1 <= x < %d. RelType=0x%X, at section %d, offset 0x%" FMT_L_PRFX "X\n",
				relSymIdx, relSymIdx, orptr->numSymbols, relRelType, orptr->secToRel->localID, orptr->r_offset);
		return;
	}
	symPtr = orptr->ourSymbols + relSymIdx;
	elfSym = symPtr->elfSym;
	symType = ELF32_ST_TYPE(elfSym->st_info);
	if ( symType == STT_SECTION )
	{
		/* The shndx is actually an index into the sections */
		segPtr = orptr->ourSections + elfSym->st_shndx;
		symLocalID = segPtr->localID;
	}
	else
		symLocalID = symPtr->localID;
	switch (orptr->ehdr->e_machine)
	{
	case EM_68K:
		if ( relRelType != 1 )
		{
			fprintf(stderr,"Unsupported m68k relocation type of %d (0x%02X). symId=%d, localID=%d, offset=0x%08X, addend=0x%08X\n",
					relRelType, relRelType, relSymIdx, symLocalID, orptr->r_offset, orptr->r_addend);
			++orptr->params->errors;
			break;
		}
		outputOrg(orptr);
		tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "l":"L";
		outputRel(orptr,symLocalID,tag);
		break;
	case EM_386:
		fprintf(stderr,"ERROR: Unsupported i386 REL record found: Section 0x%02X, relType 0x%02X, symIdx 0x%04X, localID %d, offset 0x%08X, r_addend 0x%08X. IGNORED\n",
				orptr->secToRel->localID,
				relRelType,
				relSymIdx,
				symLocalID,
				orptr->r_offset,
				orptr->r_addend
				);
		++orptr->params->errors;
		break;
	case EM_MIPS:
	case EM_MIPS_RS3_LE:
	case EM_MIPS_X:
		switch (relRelType)
		{
		case R_MIPS_16:		/* 16 bits */
			outputOrg(orptr);
			orptr->r_addend = getElfHalf(orptr->ehdr, (uint8_t *)orptr->secToRel->elfData->d_buf + orptr->r_offset);
			tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "w":"W";
			outputRel(orptr,symLocalID,tag);
			break;
		case R_MIPS_32:		/* 32 bits */
			outputOrg(orptr);
			orptr->r_addend = getElfWord(orptr->ehdr, (uint8_t *)orptr->secToRel->elfData->d_buf + orptr->r_offset);
			tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "l":"L";
			outputRel(orptr,symLocalID,tag);
			break;
		case R_MIPS_REL32:	/* PC relative 32 bits */
			outputOrg(orptr);
			tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "l":"L";
			orptr->r_addend = getElfWord(orptr->ehdr, (uint8_t *)orptr->secToRel->elfData->d_buf + orptr->r_offset);
			if ( orptr->r_addend )
			{
				fprintf(orptr->output, "%%%d %d + %%%d %d + -:%s\n",
						symLocalID,
						orptr->r_addend,
						orptr->secToRel->localID,
						orptr->r_offset+4,
						tag
						);
			}
			else
			{
				fprintf(orptr->output, "%%%d %%%d %d + -:%s\n",
						symLocalID,
						orptr->secToRel->localID,
						orptr->r_offset+4,
						tag
						);
			}
			break;
		case R_MIPS_26:		/* 4 (jump) */
			{
				Elf32_Word opcode;
				const Elf32_Word OpMask = 0xFC000000;
				outputOrg(orptr);
				opcode = getElfWord(orptr->ehdr, (uint8_t *)orptr->secToRel->elfData->d_buf + orptr->r_offset);
				orptr->r_addend = (opcode & ~OpMask) << 2;
				opcode = (opcode&OpMask);
				if ( orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB )
					tag = "l";
				else
					tag = "L";
				fprintf(orptr->output, "%%%d %d + 2 > 67108863 & %d |:%s\n",
						symLocalID,
						orptr->r_addend,
						opcode,
						tag
						);
			}
			break;
		case R_MIPS_HI16:	/* 5 (upper 16 bits) */
			outputOrg(orptr);
			tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "w":"W";
			orptr->r_addend = getElfHalf(orptr->ehdr, (uint8_t *)orptr->secToRel->elfData->d_buf + orptr->r_offset);
			orptr->r_addend <<= 16;
			if ( orptr->r_addend )
			{
				fprintf(orptr->output, "%%%d %d + 16 > 65535 &:%s\n",
						symLocalID,
						orptr->r_addend,
						tag
						);
			}
			else
			{
				fprintf(orptr->output, "%%%d 16 > 65535 &:%s\n",
						symLocalID,
						tag
						);
			}
			break;
		case R_MIPS_LO16:	/* 6 (lower 16 bits) */
			outputOrg(orptr);
			tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "w":"W";
			orptr->r_addend = getElfHalf(orptr->ehdr, (uint8_t *)orptr->secToRel->elfData->d_buf + orptr->r_offset);
			if ( orptr->r_addend )
			{
				fprintf(orptr->output, "%%%d %d + 65535 &:%s\n",
						symLocalID,
						orptr->r_addend,
						tag
						);
			}
			else
			{
				fprintf(orptr->output, "%%%d 65535 &:%s\n",
						symLocalID,
						tag
						);
			}
			break;
		case R_MIPS_GPREL16:	/* 7 (GP relative 16 bits) */
			outputOrg(orptr);
			tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "i":"I";
			orptr->r_addend = getElfHalf(orptr->ehdr, (uint8_t *)orptr->secToRel->elfData->d_buf + orptr->r_offset);
			if ( (orptr->r_addend&0x8000) )
				orptr->r_addend |= 0xFFFF0000;
			if ( orptr->r_addend )
			{
				fprintf(orptr->output, "%%%d %d + %%%d -:%s\n",
						symLocalID,
						orptr->r_addend,
						orptr->numSymbols,
						tag
						);
			}
			else
			{
				fprintf(orptr->output, "%%%d %%%d -:%s\n",
						symLocalID,
						orptr->numSymbols,
						tag
						);
			}
			break;
		case R_MIPS_PC16:		/* 10 (PC relative 16 bits) */
			outputOrg(orptr);
			tag = orptr->ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "w":"W";
			fprintf(orptr->output, "%%%d %%%d %d + - 2 > 65535 &:%s\n",
					symLocalID,
					orptr->secToRel->localID,
					orptr->r_offset+4,
					tag
					);
			break;
		default:
			fprintf(stderr, "ERROR: Unsupported MipsEl REL record found: Section 0x%02X, relType 0x%02X, symIdx 0x%04X, localID %d, offset 0x%08X, r_addend 0x%08X. IGNORED\n",
					orptr->secToRel->localID,
					relRelType,
					relSymIdx,
					symLocalID,
					orptr->r_offset,
					orptr->r_addend
					);
			++orptr->params->errors;
			break;
		}
		break;
	default:
		fprintf(stderr,"ERROR: Undefined machine type of 0x%04X. REL record found: Section 0x%02X, relType 0x%02X, symIdx 0x%04X, localID %d, offset 0x%08X, r_addend 0x%08X. IGNORED\n",
				orptr->ehdr->e_machine,
				orptr->secToRel->localID,
				relRelType,
				relSymIdx,
				symLocalID,
				orptr->r_offset,
				orptr->r_addend
				);
		++orptr->params->errors;
		break;
	}
}

static int insertIntoSorted(int numSorted, Elf32_Sym **sortedList, Elf32_Sym *sym)
{
	int ii;
	/* Entries sorted high to low */
	for ( ii = 0; ii < numSorted; ++ii )
	{
		if ( sym->st_size >= sortedList[ii]->st_size )
		{
			int scootCnt = numSorted-ii;
			/* scoot everybody down one slot */
			memmove(sortedList+ii+1,sortedList+ii,scootCnt*sizeof(Elf32_Sym *));
			break;
		}
	}
	/* add new one to wherever it goes in the list */
	sortedList[ii] = sym;
	++numSorted;
	return numSorted;
}

static void cvtSections(ElfParams_t *params, FILE *output)
{
	char cpu[64];
	char timeBuf[64];
	time_t now = time(NULL);
	struct tm *tmPtr;
	Elf_Scn *scn;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	int doMipsBss=0, ii, sects, localId, numSymbols;
	char *sect_strings;
	const char *nm;
	Elf32_Ehdr *ehdr;
	Elf32_Shdr **sections, *mipsCommon=NULL;;
	Elf_Data **section_data;
	OurSection_t *ourSections;
	OurSymbol_t *ourSymbols;
	Elf *elf;
	OurElf_Rel_t orp;
	char *sym_strs = NULL;
	
	elf = params->elf;
	ehdr = params->ehdr;
	sections = params->sections;
	section_data = params->section_data;
	ourSections = params->ourSections;
	orp.params = params;
	orp.ehdr = ehdr;
	orp.output = output;
	orp.section_data = section_data;
	orp.ourSections = ourSections;
	ourSymbols = NULL;
	tmPtr = localtime(&now);
	switch ( ehdr->e_machine )
	{
	case EM_386:
		strncpy(cpu, "x86", sizeof(cpu));
		break;
	case EM_68K:
		strncpy(cpu, "M68K", sizeof(cpu));
		break;
	case EM_MIPS:
		snprintf(cpu, sizeof(cpu), "MIPS RxK %sE", ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "L":"B");
		doMipsBss = 1;
		break;
	case EM_MIPS_RS3_LE:
		snprintf(cpu, sizeof(cpu), "MIPS R3K %sE", ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "L":"B");
		doMipsBss = 1;
		break;
	case EM_MIPS_X:
		snprintf(cpu, sizeof(cpu), "Stanford MIPS %sE", ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "L":"B");
		doMipsBss = 1;
		break;
	default:
		snprintf(cpu, sizeof(cpu), "Unknown (%d), %s endian", ehdr->e_machine, ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "Little":"Big");
		break;
	}
	strftime(timeBuf, sizeof(timeBuf), "%F %T", tmPtr);
	fprintf(output, ".id \"translator\" \"elf2ol %s (%d bit)\"\n", VERSION, sizeof(void *)==(size_t)4 ? 32:64);
	fprintf(output, ".id \"mod\" \"%s\"\n", params->target);
	fprintf(output, ".id \"date\" \"%s\"\n", timeBuf);
	fprintf(output, ".id \"target\" \"%s\"\n", cpu);
	fprintf(output, ".seg {.ABS.}%%1 1 1 {abcu}\n");
	fprintf(output, ".len %%1 0\n");
	fprintf(output, ".abs %%1 0\n");
	localId = 2;
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
	if ( doMipsBss )
	{
		for ( ii = 1; (shdr = sections[ii]) && ii < ehdr->e_shnum; ++ii )
		{
			/* Look for .bss section */
			if ( (shdr->sh_type == SHT_PROGBITS || shdr->sh_type == SHT_NOBITS) && (shdr->sh_flags&SHF_ALLOC) )
			{
				nm = sect_strings ? sect_strings + shdr->sh_name : "";
				if ( !strcmp(nm, ".bss") )
				{
					/* found it. Save pointer to it */
					mipsCommon = shdr;
				}
				continue;
			}
			/* Look for symbol section */
			if ( shdr->sh_type == SHT_SYMTAB )
			{
				int jj, numSorted;
				Elf32_Sym *sym, **sortedSyms;
				if ( !mipsCommon )
				{
					fprintf(stderr,"ERROR: Did not find .bss section in MIPSEL records\n");
					break;
				}
				data = section_data[ii];    /* get section data */
				sym = (Elf32_Sym *)data->d_buf;
				numSymbols = data->d_size / sizeof(Elf32_Sym);
				sortedSyms = (Elf32_Sym **)calloc(numSymbols,sizeof(Elf32_Sym *));
				numSorted = 0;
				for ( jj = 0; jj < numSymbols; ++jj, ++sym )
				{
					if ( sym->st_shndx == SHN_COMMON )
						numSorted = insertIntoSorted(numSorted, sortedSyms, sym);
				}
				Elf32_Word base = 0;
				for (jj=0; jj < numSorted; ++jj)
				{
					base = (base+7)&-8;	/* Align base addr */
					sym = sortedSyms[jj];
					sym->st_value = base;
					base += sym->st_size;
				}
				mipsCommon->sh_size = base;
				free(sortedSyms);
				break;
			}
		}
	}
	// Fill the sections as appropriate
	for ( ii = 0; (shdr = sections[ii]) && ii < ehdr->e_shnum; ++ii )
	{
		if ( (shdr->sh_type == SHT_PROGBITS || shdr->sh_type == SHT_NOBITS) && (shdr->sh_flags&SHF_ALLOC) )
		{
			  // Program data (.text or other RO code sections )
			nm = sect_strings ? sect_strings + shdr->sh_name : "";
			if ( params->remap )
			{
				if ( !strcmp(nm, ".bss") )
					nm = "seg$bss";
				else if ( !strcmp(nm,".text") )
					nm = "seg$text";
				else if ( !strcmp(nm,"_.text.startup") )
					nm = "seg$text$startup";
				else if ( !strcmp(nm, ".data") )
					nm = "seg$data";
				else if ( !strcmp(nm, ".rodata") )
					nm = "seg$rodata";
				else if ( !strcmp(nm,".rodata.str1.1") )
					nm = "seg$string";
			}
			if ( shdr->sh_type == SHT_PROGBITS && (shdr->sh_flags & SHF_WRITE) && shdr->sh_size )
				fprintf(stderr,"Warning: Section %s is writable. Must be read-only\n", nm);
			ourSections[ii].elfSection = shdr;
			ourSections[ii].elfData = section_data[ii];
			ourSections[ii].localID = localId;
			ourSections[ii].sectionName = nm;
			++localId;
			if ( mipsCommon && mipsCommon == shdr )
			{
				printf("Found mipsCommon is section %s. size is set to %d\n", nm, shdr->sh_size);
			}
			fprintf(output, ".seg {%s}%%%d %d %d {%s%s}\n",
					nm,
					ourSections[ii].localID,
					shdr->sh_addralign == 1 ? 0 : 1,
					shdr->sh_addralign == 1 ? 0 : 1,
					(shdr->sh_flags&SHF_WRITE) ? "" : "r",
					(shdr->sh_type == SHT_NOBITS) ? "" : "u"
					);
			fprintf(output,".len %%%d %d\n",
					ourSections[ii].localID,
					shdr->sh_size);
			continue;
		}
		if ( shdr->sh_type == SHT_SYMTAB )
		{
			int jj;
			Elf32_Sym *sym;
			Elf32_Shdr *strhdr;
			int have_gp = 0;
			OurSymbol_t *ourSymPtr;
			
			strhdr = sections[shdr->sh_link];
			if ( strhdr && strhdr->sh_type == SHT_STRTAB )
				sym_strs = (char *)section_data[shdr->sh_link]->d_buf;
			data = section_data[ii];    /* get section data */
			sym = (Elf32_Sym *)data->d_buf;
			orp.symStrs = sym_strs;
			numSymbols = data->d_size / sizeof(Elf32_Sym);
			ourSymbols = (OurSymbol_t *)calloc(numSymbols+1,sizeof(OurSymbol_t));
			orp.numSymbols = numSymbols;
			orp.ourSymbols = ourSymbols;
			ourSymPtr = ourSymbols;
			for ( jj = 0; jj < numSymbols; ++jj, ++sym, ++ourSymPtr )
			{
				int bi, ty;
				ourSymPtr->elfSym = sym;
				ourSymPtr->localID = localId;
				ourSymPtr->symbolName = sym_strs + sym->st_name;
				if ( !strcmp(ourSymPtr->symbolName,"_gp") )
				{
					have_gp = 1;
					orp.gpLocalID = localId;
				}
				++localId;
				if ( (bi=ELF32_ST_BIND(sym->st_info)) )
				{
					if ( sym_strs )
						nm = sym_strs + sym->st_name;
					else
						nm = "";
					ty = ELF32_ST_TYPE(sym->st_info);
					if ( ty == STT_SECTION )
						ourSymPtr->sectionPtr = ourSections + sym->st_shndx;
					if ( bi == STB_GLOBAL || bi == STB_LOCAL )
					{
						if ( sym->st_shndx > 0 && sym->st_shndx < ehdr->e_shnum )
						{
#if 0
#define SHN_UNDEF	0		/* Undefined section */
#define SHN_LORESERVE	0xff00		/* Start of reserved indices */
#define SHN_LOPROC	0xff00		/* Start of processor-specific */
#define SHN_BEFORE	0xff00		/* Order section before all others
					   (Solaris).  */
#define SHN_AFTER	0xff01		/* Order section after all others
					   (Solaris).  */
#define SHN_HIPROC	0xff1f		/* End of processor-specific */
#define SHN_LOOS	0xff20		/* Start of OS-specific */
#define SHN_HIOS	0xff3f		/* End of OS-specific */
#define SHN_ABS		0xfff1		/* Associated symbol is absolute */
#define SHN_COMMON	0xfff2		/* Associated symbol is common */
#endif
							/* FIXME: Convert st_shndx == SHN_xxx to section index */
							if ( sym->st_value )
							{
								fprintf(output, ".def%c {%s}%%%d %%%d %d +\n",
										bi == STB_GLOBAL ? 'g' : 'l',
										nm,
										ourSymPtr->localID,
										ourSections[sym->st_shndx].localID,
										sym->st_value);
							}
							else
							{
								fprintf(output, ".def%c {%s}%%%d %%%d\n",
										bi == STB_GLOBAL ? 'g' : 'l',
										nm,
										ourSymPtr->localID,
										ourSections[sym->st_shndx].localID);
							}
						}
						else if ( bi == STB_GLOBAL && (sym->st_shndx == SHN_ABS || sym->st_shndx == SHN_COMMON || sym->st_shndx == SHN_UNDEF) )
						{
							fprintf(output, ".ext {%s}%%%d\n",
									nm,
									ourSymPtr->localID);
						}
					}
					else if ( bi == STB_WEAK )
					{
						fprintf(stderr,"Warning: No support in ol format for weak variables: %s%%%d\n", nm, ourSymbols[jj].localID);
					}
				}
			}
			if ( !have_gp )
			{
				fprintf(output, ".ext {_gp}%%%d\n", localId);
				orp.gpLocalID = localId;
			}
			continue;
		}
	}
	for ( ii = 1; ii < ehdr->e_shnum && (shdr = sections[ii]); ++ii )
	{
		Elf_Data *eptr=section_data[ii];
		nm = sect_strings ? sect_strings + shdr->sh_name : "";
		if ( eptr && shdr->sh_type == SHT_PROGBITS  && (shdr->sh_flags&SHF_ALLOC) )
		{
			if ( eptr->d_buf && eptr->d_size )
			{
				size_t tot;
				uint8_t *bptr;

				fprintf(output, ".org %%%d 0\n", ourSections[ii].localID);
				tot = 0;
				bptr = (uint8_t *)eptr->d_buf;
				while ( tot < eptr->d_size )
				{
					static const char Hex[] = "0123456789ABCDEF";
					char *cp, txtLine[80];
					size_t jj, lim;

					lim = 32;
					if ( eptr->d_size-tot < lim )
						lim = eptr->d_size-tot;
					cp = txtLine;
					*cp++ = '\'';
					for ( jj = 0; jj < lim ; ++jj )
					{
						uint8_t ch = *bptr++;
						*cp++ = Hex[(ch>>4)&0xF];
						*cp++ = Hex[ch&0xF];
					}
					*cp++ = '\'';
					*cp++ = '\n';
					*cp = 0;
					fputs(txtLine,output);
					tot += lim;
				}
			}
			else if ( params->verbose )
				printf("Section %d (\"%s\") has no data\n", ii, nm);
		}
	}
	if ( params->verbose )
		printf("Looking for REL directives:\n");
	for ( ii = 1; ii < ehdr->e_shnum && (shdr = sections[ii]); ++ii )
	{
		Elf_Data *eptr=section_data[ii];
		nm = sect_strings ? sect_strings + shdr->sh_name : "";
		
		if ( params->verbose )
		{
			printf("Checking section %d {%s}, eptr=%p, eptr->d_buf=%p, eptr->d_size=%ld, shdr->sh_flags=0x%X:\n",
				   ii,
				   nm,
				   (void *)eptr,
				   (void *)(eptr ? eptr->d_buf : NULL),
				   eptr ? eptr->d_size : 0,
				   shdr->sh_flags
				   );
		}
		if (    eptr
			 && eptr->d_buf
		     && eptr->d_size
			)
		{
			if ( shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA )
			{
				Elf32_Word jj;
				
				jj = shdr->sh_info;
				if ( jj <= 0 || jj >= ehdr->e_shnum )
				{
					fprintf(stderr,"Found bad section index of 0x%X in REL record in section %d {%s}\n",
							jj, ii, nm);
					continue;
				}
				if ( !ourSections[jj].elfSection || !(ourSections[jj].elfSection->sh_flags&SHF_ALLOC) )
					continue;
				if ( params->verbose )
					printf("\tFound section %d {%s} needing relocation. sh_info=0x%X, sh_flags=0x%X, sh_type=0x%X\n", ii, nm, jj, shdr->sh_flags, shdr->sh_type);
				orp.secToRel = ourSections+jj;
				if ( shdr->sh_type == SHT_REL )
				{
					Elf32_Rel *rptr, *endPtr;
					endPtr = (Elf32_Rel *)((uint8_t *)eptr->d_buf + eptr->d_size);
					rptr = (Elf32_Rel *)eptr->d_buf;
					orp.r_addend = 0;
					for (jj=0; rptr < endPtr; ++jj, ++rptr )
					{
/*						int symIdx = ELF32_R_SYM(rptr->r_info); */
						orp.r_info = rptr->r_info;
						orp.r_offset = rptr->r_offset;
						outputRelExpr(&orp);
					}
				}
				else
				{
					Elf32_Rela *rptr, *endPtr;
					endPtr = (Elf32_Rela *)((uint8_t *)eptr->d_buf + eptr->d_size);
					rptr = (Elf32_Rela *)eptr->d_buf;
					for (jj=0; rptr < endPtr; ++jj, ++rptr )
					{
						orp.r_addend = rptr->r_addend;
						orp.r_info = rptr->r_info;
						orp.r_offset = rptr->r_offset;
						outputRelExpr(&orp);
					}
				}
			}
			continue;
		}
		if ( params->verbose )
			printf("Section %d (\"%s\") has no data\n", ii, nm);
	}
	if ( params->dumpCvt )
	{
		OurSymbol_t *ourSymPtr;
		
		printf("Sections (%d total):\n", ehdr->e_shnum);
		for (ii=0; ii < ehdr->e_shnum && (shdr = sections[ii]); ++ii)
		{
			if ( ourSections[ii].localID )
			{
				char title[64];
				printf("0x%04X ourSection: localID %3d, %s\n",
					   ii,
					   ourSections[ii].localID,
					   ourSections[ii].sectionName);
				snprintf(title,sizeof(title),"0x%04X elfSection: ", ii);
				showIndividualSection(params,sect_strings,title,shdr);
			}
		}
		printf("Symbols (%d total):\n", numSymbols);
		ourSymPtr = ourSymbols;
		for (ii=0; ii < numSymbols; ++ii, ++ourSymPtr)
		{
			const Elf32_Sym *sym = ourSymPtr->elfSym;
			printf("0x%04X: ourSymbol: localID 0x%04X(%d), elf=%p, seg=%p, name {%s}\n",
				   ii,
				   ourSymPtr->localID,
				   ourSymPtr->localID,
				   (void *)ourSymPtr->elfSym,
				   (void *)ourSymPtr->sectionPtr,
				   ourSymPtr->symbolName
				   );
			if ( sym )
			{
				char title[64];
				snprintf(title,sizeof(title),"        elfSymbol: ");
				showIndividualSymbol(params, sym_strs, title, sym);
			}
		}
	}
	if ( ourSymbols )
		free(ourSymbols);
}

static int help_em(const char *errMsg, const char *title)
{
	if ( errMsg )
		fprintf(stderr,"%s\n", errMsg);
	fprintf(stderr,
			"Usage: %s [-drv][-o outfile] file\n"
			"Where:\n"
			"-d       = dump the input file to stdout (other options ignored)\n"
			"-D       = dump our section and symbol tables\n"
			"-l limit = set max limit of hexdump (only when using -d)\n"
			"-r       = remap the section names (only when using -o)\n"
			"-R       = dump just .text section in .rom format\n"
			"-v       = set verbose\n"
			"-o path  = path to output name (should be named: <bla-bla>.ol)\n"
			,title);
	return 1;
}

int main(int argc, char *argv[])
{
	Elf * elf,*arf;
	Elf32_Ehdr *ehdr;
	int filedes, sts;
	Elf_Cmd cmd;
	Hexdump hd(0, NULL);
	FILE *output=NULL;
	int opt, verbose=0, dumpIt=0, dumpCvt=0, remap=0, dump2Rom=0;
	size_t limit=0;
	char *endp, *inpName, *target=NULL;
	char cc, *outputFilename=NULL;
	ElfParams_t showParams;
	unsigned char elfHeader[5];
	
	while ( (opt = getopt(argc, argv, "dDl:o:rRv")) != -1 )
	{
		switch (opt)
		{
		case 'l':
			endp = NULL;
			limit = strtol(optarg,&endp,0);
			if ( !endp )
			{
				printf("Invalid limit: %s\n", optarg);
				return 1;
			}
			cc = toupper(*endp);
			if ( cc == 'K' )
				limit *= 1024;
			else if ( cc == 'M' )
				limit *= 1024*1024;
			else if ( cc )
			{
				printf("Limit multiplier can only be K or M: %s\n", optarg);
				return 1;
			}
			break;
		case 'd':
			dumpIt = 1;
			break;
		case 'D':
			dumpCvt = 1;
			break;
		case 'o':
			outputFilename = optarg;
			break;
		case 'R':
			dump2Rom = 1;
			break;
		case 'r':
			remap = 1;
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

	if ( !dumpIt && !dump2Rom && !outputFilename )
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
	sts = read(filedes,elfHeader,sizeof(elfHeader));
	if ( sts != sizeof(elfHeader) )
	{
		perror("Failed to read input to determine 32/64 mode");
		close(filedes);
		return 4;
	}
	if ( elfHeader[EI_CLASS] != ELFCLASS32 )
	{
		if ( elfHeader[EI_CLASS] == ELFCLASS64 )
			printf("Input is elf64 format. This tool only handles elf32 input files.\n");
		else
			printf("Input is not elf32 format. Is type 0x%02X. This tool only handles elf32 input files.\n", elfHeader[EI_CLASS]);
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
		return 7;
	}
	if ( !dumpIt && !dump2Rom )
	{
		output = fopen(outputFilename, "w");
		if ( !output )
		{
			perror("Failed to open output");
			close(filedes);
			return 8;
		}
		target = outputFilename;
	}
	cmd = ELF_C_READ;
	while ( (elf = elf_begin(filedes, cmd, arf)) != 0 )
	{
		if ( (ehdr = elf32_getehdr(elf)) != 0 )
		{
			memset(&showParams,0,sizeof(showParams));
			showParams.elf = elf;
			showParams.ehdr = ehdr;
			showParams.remap = remap;
			showParams.target = target;
			showParams.verbose = verbose;
			showParams.hd = &hd;
			showParams.limit = limit;
			showParams.dumpCvt = dumpCvt;
			if ( ehdr->e_shnum )
			{
				showParams.sections = (Elf32_Shdr **)calloc(ehdr->e_shnum, sizeof(Elf32_Shdr *));
				showParams.section_data = (Elf_Data **)calloc(ehdr->e_shnum, sizeof(Elf_Data *));
				showParams.ourSections = (OurSection_t *)calloc(ehdr->e_shnum, sizeof(OurSection_t));
			}
			if ( dumpIt )
				showSections(&showParams);
			else if ( dump2Rom )
				showInRomFormat(&showParams);
			else
				cvtSections(&showParams, output);
			if ( showParams.sections )
				free(showParams.sections);
			if ( showParams.section_data )
				free(showParams.section_data);
			if ( showParams.ourSections )
				free(showParams.ourSections);
		}
		cmd = elf_next(elf);
		elf_end(elf);
	}
	if ( output )
		fclose(output);
	elf_end(arf);
	close(filedes);
	return showParams.errors ? 1 : 0;
}
