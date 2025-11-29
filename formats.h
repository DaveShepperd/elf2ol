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
