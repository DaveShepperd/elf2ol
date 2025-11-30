//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
//Copyright GFX Construction Inc.
//All rights reserved.
//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

#include "lib_hexdump.h"

/**
 * @file lib_hexdump.cpp
 * 
 * @author shepperd (4/26/2009)
 * 
 */

pthread_mutex_t Hexdump::mMutex = PTHREAD_MUTEX_INITIALIZER;

// See comments in lib_dump.h for details of how to use this

// Internal workhorse function. Not directly called by user code
int Hexdump::displayIt( int lim, int addr, const uint8_t *iBuff, const char *prefix )
{
	char line[maxColumns*5+256], *lbase, *lptr;
	static const char hex2asc[] = "0123456789ABCDEF";
	const uint8_t *tBuff;
	int col, spaces;

	memset(line, ' ', sizeof(line)-1);		// Preclear the output buffer
	lbase = line;
	if ( mFormat )
	{
		if ( prefix )
		{
			col = strlen(prefix);
			if ( col > mFormat+8 )
				col = mFormat+8;
			if ( col > (int)sizeof(line)-1 )
				col = sizeof(line)-1;
			strncpy(line, prefix, col);
			line[col] = ' ';
		}
		lbase = line + mFormat+8;
	}
	lbase += snprintf(lbase, sizeof(line)-(mFormat+8), "%04X: ", addr); /* start the line with an address (offset) */
	line[sizeof(line)-1] = 0;				// Make sure the line is terminated with a null
	tBuff = iBuff;							// Remember where we started in the buffer
	for (lptr=lbase, col=0; col < lim; ++col, ++iBuff) // Dump the whole line
	{
		if ( col && !(col&7) )		 		// Add an extra space every 8
		{
			++lptr;
			if (col == 16)					// ... and an another extra at 16
			{
				++lptr;
			}
		}
		*lptr++ = hex2asc[*iBuff>>4];		// Convert binary to ascii
		*lptr++ = hex2asc[*iBuff&0xF];
		++lptr;								// Follow with a space
	}
	// Compute how many spaces to skip to get to the ascii field dump
	spaces = mColumns*3 + mColumns/32 + mColumns/8 + 1;
	lptr = lbase + spaces;					// Point to ascii dump buffer
	*lptr++ = '|';							// Delimit the ascii dump with a pair of '|'s
	for ( col=0; col < lim; ++col, ++tBuff )
	{
		*lptr++ = isprint(*tBuff) ? *tBuff : '.';	// Dump the buffer in ascii
	}
	lbase[spaces+mColumns+1] = '|';
	lbase[spaces+mColumns+2] = 0;			// Terminate with a null
	if ( mOutput )							// output the line
		mOutput(line);
	else
		puts(line);
	return 0;
}

// See lib_hexdump.h for calling details.
int Hexdump::dumpIt( const char *msg, const uint8_t *iBuff, int len )
{
//	const uint8_t *tBuff;
	char msgLine[256];
	uint8_t savedLine[maxColumns];
	int skipped=0, savedAddr=0, addr=0, lim, skipCol=0;
	
	// If so asked, grab a mutex to prevent interlacing of dumps in the output
	if ( mInterlock )
	{	
		pthread_mutex_lock( &mMutex );
//		if ( mOutput )
//			logLock();
	}
	if ( mFormat )
	{
		if ( msg )
			// User provided a message to prefix, display it along with the length
			skipCol = snprintf( msgLine, sizeof(msgLine), "%-*.*s (%3d): ", mFormat, mFormat, msg, len );
		else
			// Else just display the length
			skipCol = snprintf( msgLine, sizeof(msgLine), "Len %d: ", len );
	}
	else
	{
		if ( msg && msg[0] )
			// User provided a message to prefix, display it along with the length
			snprintf( msgLine, sizeof(msgLine), "%sLen: %d (0x%X)", msg, len, len );
		else
			// Else just display the length
			snprintf( msgLine, sizeof(msgLine), "Len: %d (0x%X)", len, len );
		if ( mOutput )
			mOutput( msgLine );
		else
			puts( msgLine );
	}
	// If there's a max to output, limit our length
	if ( mLimit && len > mLimit )
		len = mLimit;
	// While there's something to output
	while ( len > 0)
	{
		// Get the line length and limit it to dump length
		lim = mColumns;
		if ( lim > len )
			lim = len;
		if ( addr && len >= lim )
		{
			// Not the first line and if the last, is at least the same length as all the others
			if ( !memcmp( iBuff, savedLine, lim) )
			{
				// Line matches the previous one, so skip display
				++skipped;
				// Remember what address belongs to the saved line
				savedAddr = addr;
				if ( len > lim )
				{
					// There're more lines after this one, so just advance pointers and loop
					len -= lim;
					addr += lim;
					iBuff += lim;
					continue;
				}
			}
		}
		// Either the first line or this line doesn't match the previous or it's the last line
		if ( skipped )
		{
			if ( skipped > 1 )
			{
				// If we skipped the display of more than one line, output some stars
				memset(msgLine, ' ', skipCol);
				memset(msgLine+skipCol,'*',5);
				msgLine[skipCol+5] = 0;
				if ( mOutput )
					mOutput(msgLine);
				else
					puts(msgLine);
				msgLine[0] = 0;
			}
			// Then output the last saved line too
			displayIt(lim,savedAddr,savedLine, msgLine);
			msgLine[0] = 0;
		}
		// If we haven't skipped any or the address of the current line is different than the saved line
		if ( !skipped || savedAddr != addr )
		{	
			displayIt( lim, addr, iBuff, msgLine );
			msgLine[0] = 0;
		}
		// Save a copy of this line for next time
		memcpy( savedLine, iBuff, lim );
		// Advance the pointers and loop
		savedAddr = addr;
		iBuff += lim;
		addr += lim;
		len -= lim;
		skipped = 0;
	}
	if ( mInterlock )
	{
		pthread_mutex_unlock( &mMutex );
//		if ( mOutput )
//			logUnlock();
	}
	return 0;
}

int Hexdump::setFormat( int fixed )
{
	int old = mFormat;

	if ( fixed < 0 || fixed > 255-10 )
		return -1;
	mFormat = fixed;
	return old;
}

