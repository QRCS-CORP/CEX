#ifndef _CEX_GF2MROOTFIND_H
#define _CEX_GF2MROOTFIND_H

#include "CexDomain.h"
#include "bit_ops.h"
#include "GF2m_Field.h"
#include "gf2m_decomp_rootfind_state.h"

NAMESPACE_MCELIECE
/**
* GF(2^m) field for m = [2...16]
*/
class gf2m_rootfind_dcmp
{
public:

	/*
	* !! Attention: assumes gf2m is 16bit !!
	*/
#if 0
	gf2m brootf_decomp__gray_to_lex(gf2m gray)
	{
		static_assert(sizeof(gf2m) == 2, "Expected size");
		gf2m result = gray ^ (gray >> 8);
		result ^= (result >> 4);
		result ^= (result >> 2);
		result ^= (result >> 1);
		return result;
	}
#endif

	static std::vector<gf2m> find_roots_gf2m_decomp(const polyn_gf2m & polyn, uint32_t code_length)
	{
		gf2m_decomp_rootfind_state state(polyn, code_length);
		return state.find_roots(polyn);
	}

};

NAMESPACE_MCELIECEEND
#endif