/*
    lib_hexdump.ih - Generic hex dump library routine.

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

#ifndef _LIB_HEXDUMP_H_
#define _LIB_HEXDUMP_H_ 1

/** @file lib_hexdump.h
 *  
 **/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <stdbit.h>

/**
 * Hexdump - Dump a block of data in hex. Optionally print a 
 * prefix line, set the width, a pointer to an output function, 
 * a maximum number of bytes to dump and set an interlock to 
 * prevent output from multiple threads from interlacing the 
 * output. 
 * 
 * @author shepperd (4/26/2009)
 */
class Hexdump
{
private:
    static pthread_mutex_t mMutex;

    enum
    {
        maxColumns = 32     // Change this at your peril
    };
    int mColumns;       ///< Number of columns to output (4, 8, 16 or 32)
    int mFormat;         ///< Format control
    int displayIt( int len, int addr, const uint8_t *iBuff, const char *prefix );
public:

    /**
     * Set the output limit. 0 (the default) = no limit
     * 
     */
    int mLimit;         ///< Limit on output (0=no limit)

    /**
     * Set a pointer to an output function. If NULL, outputs via a 
     * 'puts()' to stdout. Note, no trailing newline is appended to 
     * each line. It is the responsibility of the output function to 
     * handle newlines. 
     *  
     * At entry: 
     * @param string - String to output 
     * At exit: 
     * @return - return value ignored 
     * 
     */
    int (*mOutput)(const char *string); ///< Pointer to output function

    /**
     * Set interlocking. If 1, output is confined to that from a 
     * single thread. If 0, no interlocking is performed. Default is 
     * off. 
     * 
     */
    bool mInterlock;    ///< Set if output is to be interlocked from other threads

    /**
     * Get the current width. 
     *  
     * @return int - number of columns of width currently set for 
     *         the dump.
     */
    inline int getWidth( void )
    {
        return mColumns;
    }

    /**
     * Set the current width
     * 
     * @param newWidth - Sets a new number of columns to dump. Will 
     *                 limit to a high of 32 and a low of 4 with
     *                 intervening values of only 16 or 8. If
     *                 'newWidth' is 0, the column will be set to
     *                 the max of 32.
     * 
     * @return int - the previously set number of columns.
     */
    inline int setWidth( int newWidth )
    {
        int oldW = mColumns;
        if ( !newWidth )
            newWidth = maxColumns;
        if ( newWidth >= maxColumns )
            newWidth = maxColumns;
        else if ( newWidth >= maxColumns/2 )
            newWidth = maxColumns/2;
        else if ( newWidth >= maxColumns/4 )
            newWidth = maxColumns/4;
        else
            newWidth = maxColumns/8;
        mColumns = newWidth;
        return oldW;
    }

    /**
     * The constructor for this class. Requires two parameters to 
     * remind one to set them, however, they can be left as 0 and 
     * NULL respectively to accept defaults. 
     * 
     * @param columns - sets the number of columns in the dump. If 
     *                'columns' = 0, defaults to the max of 32.
     * @param output - sets a pointer to an output function. If 
     *               NULL, defaults to using 'puts()' to stdout.
     */
    Hexdump( int columns, int (*output)(const char *string) )
    {
        setWidth( columns );
        mOutput = output;
        mInterlock = false;
        mFormat = 0;
        mLimit = 0;
    }

    ~Hexdump()
    {
    }

    /**
     * dumpIt() - dump the buffer. 
     *  
     * @param msg - pointer to prefix message. A len=xx will be 
     *            appeneded to this message before output.
     * @param buffer - Pointer to buffer to dump.
     * @param buffLen - Number of bytes in buffer.
     * 
     * @return int - Always returns 0.
     */
    int dumpIt( const char *msg, const uint8_t *buffer, int buffLen );

    /**
     * setFormat() - set the output format 
     *  
     * @param fixed - if > 0 && < 245, make all lines the same 
     *              length and allow 'fixed' bytes for the 'msg'
     *              parameter passed in the dumpIt() function.
     *              Appends the len to the end of the 'msg'
     *              parameter in parens. If 0, disable fixed width
     *              formatting.
     * @return previous value of fixed or -1 if 'fixed' out of 
     *         range.
     */
    int setFormat( int fixed );
};
#endif // _LIB_HEXDUMP_H_
