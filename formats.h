/*
    formats.h - Generic header to help with those damn printf arguments
    when switching back and forth from 32 bit to 64 bit.
    
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
 * @author shepperd (01/01/2025)
 *
 */

#ifndef _FORMATS_H_
#define _FORMATS_H_ (1)

#include <inttypes.h>

#if __SIZEOF_PTRDIFF_T__ > __SIZEOF_INT__
	#if __SIZEOF_PTRDIFF_T__ > __SIZEOF_LONG__
		#define FMT_PTRDIF_PRFX "ll"
	#else
		#define FMT_PTRDIF_PRFX "l"
	#endif
#else
	#define FMT_PTRDIF_PRFX ""
#endif
#if __SIZEOF_SIZE_T__ > __SIZEOF_INT__
	#if __SIZEOF_SIZE_T__ > __SIZEOF_LONG__
		#define FMT_SZ_PRFX "ll"
	#else
		#define FMT_SZ_PRFX "l"
	#endif
#else
	#define FMT_SZ_PRFX ""
#endif
#if __SIZEOF_LONG_LONG__ > __SIZEOF_LONG__
	#define FMT_LL_PRFX "ll"
#else
	#define FMT_LL_PRFX "l"
#endif
#if __SIZEOF_LONG > __SIZEOF_INT__
	#define FMT_L_PRFX "l"
#else
	#define FMT_L_PRFX ""
#endif
#define FMT_PRFX ""

#endif	/* _FORMATS_H_*/
