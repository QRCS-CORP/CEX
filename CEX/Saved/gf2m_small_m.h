#ifndef _CEX_GF2MS_H
#define _CEX_GF2MS_H

#include "CexDomain.h"
#include "IDigest.h"
#include "IPrng.h"

NAMESPACE_MCELIECE

typedef uint16_t gf2m;

/// <summary>
/// 
/// </summary>
class gf2m_small_m
{
public:
	/**
	* Expand an input to a bit mask depending on it being being zero or non-zero
	* @param tst the input
	* @return the mask 0xFFFF if tst is non-zero and 0 otherwise
	*/
	template<typename T>
	static uint16_t expand_mask_16bit(T tst)
	{
		const uint16_t result = (tst != 0);
		return ~(result - 1);
	}

	inline static gf2m gray_to_lex(gf2m gray)
	{
		gf2m result = gray ^ (gray >> 8);
		result ^= (result >> 4);
		result ^= (result >> 2);
		result ^= (result >> 1);
		return result;
	}

	inline static gf2m lex_to_gray(gf2m lex)
	{
		return (lex >> 1) ^ lex;
	}

	inline static uint32_t bit_size_to_byte_size(uint32_t bit_size)
	{
		return (bit_size - 1) / 8 + 1;
	}

	inline static uint32_t bit_size_to_32bit_size(uint32_t bit_size)
	{
		return (bit_size - 1) / 32 + 1;
	}

	inline static uint32_t encode_gf2m(gf2m to_enc, uint8_t* mem)
	{
		mem[0] = to_enc >> 8;
		mem[1] = to_enc & 0xFF;
		return sizeof(to_enc);
	}

	inline static gf2m decode_gf2m(const uint8_t* mem)
	{
		gf2m result;
		result = mem[0] << 8;
		result |= mem[1];
		return result;
	}
};

NAMESPACE_MCELIECEEND
#endif
