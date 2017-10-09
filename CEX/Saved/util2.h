#ifndef _CEX_UTIL2_H
#define _CEX_UTIL2_H

#include "CexDomain.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class util2
{
public:

	static void store8(std::vector<byte> &out, size_t Offset, ulong in)
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

	static ulong load8(const std::vector<byte> &in, size_t Offset)
	{
		int i;
		ulong ret = in[Offset + 7];

		for (i = 6; i >= 0; i--)
		{
			ret <<= 8;
			ret |= in[Offset + i];
		}

		return ret;
	}
};

NAMESPACE_MCELIECEEND
#endif

