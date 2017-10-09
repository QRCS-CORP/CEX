#ifndef _CEX_UTIL_H
#define _CEX_UTIL_H

#include "CexDomain.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class util
{
public:

	static void store8(unsigned char *out, uint64_t in) 
	{
		out[0] = (in >> 0x00) & 0xFF;
		out[1] = (in >> 0x08) & 0xFF;
		out[2] = (in >> 0x10) & 0xFF;
		out[3] = (in >> 0x18) & 0xFF;
		out[4] = (in >> 0x20) & 0xFF;
		out[5] = (in >> 0x28) & 0xFF;
		out[6] = (in >> 0x30) & 0xFF;
		out[7] = (in >> 0x38) & 0xFF;
	}

	static void store8(unsigned char *out, size_t Offset, uint64_t in)
	{
		out[Offset] = (in >> 0x00) & 0xFF;
		out[Offset + 1] = (in >> 0x08) & 0xFF;
		out[Offset + 2] = (in >> 0x10) & 0xFF;
		out[Offset + 3] = (in >> 0x18) & 0xFF;
		out[Offset + 4] = (in >> 0x20) & 0xFF;
		out[Offset + 5] = (in >> 0x28) & 0xFF;
		out[Offset + 6] = (in >> 0x30) & 0xFF;
		out[Offset + 7] = (in >> 0x38) & 0xFF;
	}

	static uint64_t load8(const unsigned char *in, size_t Offset)
	{
		int i;
		uint64_t ret = in[Offset + 7];

		for (i = 6; i >= 0; i--)
		{
			ret <<= 8;
			ret |= in[Offset + i];
		}

		return ret;
	}

	static uint64_t load8(const unsigned char *in) 
	{
		int i;
		uint64_t ret = in[7];

		for (i = 6; i >= 0; i--) 
		{
			ret <<= 8;
			ret |= in[i];
		}

		return ret;
	}
};

NAMESPACE_MCELIECEEND
#endif

