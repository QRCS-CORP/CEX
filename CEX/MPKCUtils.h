// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_MCELIECEUTILS_H
#define CEX_MCELIECEUTILS_H

#include "CexDomain.h"

NAMESPACE_MCELIECE

/// 
/// internal
/// 

/// <summary>
// An internal McEliece utilities class
/// </summary>
class MPKCUtils
{
public:

	//~~~N6090T13 and N8192T13~~~//

	// benes.c //

	static void LayerIn(ulong Data[2][64], const ulong* Bits, uint Lgs);

	static void LayerEx(ulong* Data, const ulong* Bits, uint Lgs);

	static void ApplyBenes(byte* R, const byte* Bits, bool Reverse);

	// controlbits.c //

	static void Compose(uint W, uint N, const uint* Pi, uint* P);

	static void ComposeInv(uint N, uint* Y, const uint* X, const uint* Pi);

	static void CSwap(uint &X, uint &Y, byte Swap);

	static void CSwap63b(ulong &X, ulong &Y, byte Swap);

	static void Flow(uint W, uint &X, const uint &Y, const uint T);

	static void Invert(uint N, uint* Ip, const uint* Pi);

	static byte IsSmaller(uint A, uint B);

	static byte IsSmaller63b(ulong A, ulong B);

	static void Merge(uint N, uint* X, uint Step);

	static void Merge63b(uint N, ulong* X, uint Step);

	static void MinMax(uint &X, uint &Y);

	static void MinMax63b(ulong &X, ulong &Y);

	static void Permute(uint W, uint N, uint Offset, uint Step, const uint* P, const uint* Pi, byte* C, uint* PiFlip);

	static void PermuteBits(uint W, uint N, uint Step, uint Offset, byte* C, const uint* Pi);

	static void Sort(uint N, uint* X);

	static void Sort63b(uint N, ulong* X);

	// transpose.c //

	static void Transpose64x64(ulong* Output, const ulong* Input);

	// util.c //

	static ushort BitReverse(ushort A);

	static void Clear8(byte* A, size_t Count);

	static void Clear32(uint* A, size_t Count);

	static void Clear64(ulong* A, size_t Count);

	static uint Le8To32(const byte* Input);

	static ulong Le8To64(const byte* Input);

	static void Le32To8(byte* Output, uint Value);

	static void Le64To8(byte* Output, ulong Value);

	static ushort Load16(const byte* Input);

	static ulong Load64(const byte* Input);

	static uint Rotl32(uint Value, uint Shift);

	static ulong Rotl64(ulong Value, uint Shift);

	static uint Rotr32(uint Value, uint Shift);

	static ulong Rotr64(ulong Value, uint Shift);

	static void Store16(byte* Output, ushort A);

	static void Store64(byte* Output, ulong Input);

	static int32_t Verify(const byte* A, const byte* B, size_t Length);

	//~~~N4096T12~~~//

	static ushort Diff(ushort X, ushort Y);

	static ushort Invert(ushort X, size_t Degree);

	static ulong MaskNonZero64(ushort X);

	static ulong MaskLeq64(ushort X, ushort Y);

	static ushort Multiply(ushort X, ushort Y, size_t Degree);

	static ushort Square(ushort X, size_t Degree);

	//~~~Templates~~~//

	template<typename Array>
	inline static void Add(Array &A, const Array &B)
	{
		size_t i;

		for (i = 0; i < A.size(); ++i)
		{
			A[i] ^= B[i];
		}
	}

	template<typename Array>
	inline static void Add(Array &Output, const Array &A, const Array &B)
	{
		size_t i;

		for (i = 0; i < Output.size(); ++i)
		{
			Output[i] = A[i] ^ B[i];
		}
	}

	template<typename Array>
	inline static void AddCarry(Array &A, ulong N)
	{
		ulong carry;
		ulong t;
		size_t i;

		carry = N;

		for (i = 0; i < 8; ++i)
		{
			t = A[i] ^ carry;
			carry = A[i] & carry;
			A[i] = t;
		}
	}

	template<typename ArrayA, typename ArrayB>
	static void BenesCompact(ArrayA &Output, const ArrayB &Condition, int Reverse)
	{
		size_t cpos;
		uint low;
		int32_t inc;

		if (Reverse == 0)
		{
			inc = 32;
			cpos = 0;
		}
		else
		{
			inc = -32;
			cpos = 704;
		}

		low = 0;

		while (low < 6)
		{
			BenesHelp(Output, Condition, cpos, low);
			cpos += inc;
			++low;
		}

		TransposeCompact64x64(Output);
		low = 0;

		while (low < 6)
		{
			BenesHelp(Output, Condition, cpos, low);
			cpos += inc;
			++low;
		}

		low = 5;

		do
		{
			--low;
			BenesHelp(Output, Condition, cpos, low);
			cpos += inc;
		} 
		while (low != 0);

		TransposeCompact64x64(Output);
		low = 6;

		do
		{
			--low;
			BenesHelp(Output, Condition, cpos, low);
			cpos += inc;
		} 
		while (low != 0);
	}

	template<typename ArrayA, typename ArrayB>
	static void BenesHelp(ArrayA &Output, const ArrayB &Condition, size_t CondOffset, uint Low)
	{
		ulong diff;
		uint i;
		uint j;
		uint x;
		uint y;
		uint high;

		high = 5 - Low;

		for (j = 0; j < (1UL << Low); ++j)
		{
			x = j;
			y = (1UL << Low) + j;

			for (i = 0; i < (1UL << high); ++i)
			{
				diff = Output[x] ^ Output[y];
				diff &= Condition[CondOffset];
				++CondOffset;
				Output[x] ^= diff;
				Output[y] ^= diff;
				x += (1UL << (Low + 1));
				y += (1UL << (Low + 1));
			}
		}
	}

	template<typename ArrayA, typename ArrayB>
	inline static void CMov(const ArrayB &Input, ArrayA &Output, ulong Mask)
	{
		size_t i;

		for (i = 0; i < Output.size(); i++)
		{
			Output[i] = (Input[i] & Mask) | (Output[i] & ~Mask);
		}
	}

	template<typename ArrayA, typename ArrayB>
	inline static void Copy(const ArrayB &Input, ArrayA &Output)
	{
		size_t i;

		for (i = 0; i < Output.size(); i++)
		{
			Output[i] = Input[i];
		}
	}

	template<typename Array>
	inline static void Insert(Array &Output, const ushort N)
	{
		size_t i;

		for (i = 0; i < Output.size(); i++)
		{
			Output[i] = (N >> i) & 1;
			Output[i] = ~Output[i] + 1;
		}
	}

	template<typename ArrayA, typename ArrayB>
	static void Multiply(ArrayA &Output, const ArrayA &A, const ArrayB &B)
	{
		const size_t OUTLEN = Output.size();
		std::vector<ulong> sum(2 * OUTLEN - 1);
		std::array<ulong, 208> t;
		size_t i;

		t[0] = A[11] & B[11];
		t[1] = A[11] & B[9];
		t[2] = A[11] & B[10];
		t[3] = A[9] & B[11];
		t[4] = A[10] & B[11];
		t[5] = A[10] & B[10];
		t[6] = A[10] & B[9];
		t[7] = A[9] & B[10];
		t[8] = A[9] & B[9];
		t[9] = t[7] ^ t[6];
		t[10] = t[5] ^ t[3];
		t[11] = t[10] ^ t[1];
		t[12] = t[4] ^ t[2];
		t[13] = A[8] & B[8];
		t[14] = A[8] & B[6];
		t[15] = A[8] & B[7];
		t[16] = A[6] & B[8];
		t[17] = A[7] & B[8];
		t[18] = A[7] & B[7];
		t[19] = A[7] & B[6];
		t[20] = A[6] & B[7];
		t[21] = A[6] & B[6];
		t[22] = t[20] ^ t[19];
		t[23] = t[18] ^ t[16];
		t[24] = t[23] ^ t[14];
		t[25] = t[17] ^ t[15];
		t[26] = A[5] & B[5];
		t[27] = A[5] & B[3];
		t[28] = A[5] & B[4];
		t[29] = A[3] & B[5];
		t[30] = A[4] & B[5];
		t[31] = A[4] & B[4];
		t[32] = A[4] & B[3];
		t[33] = A[3] & B[4];
		t[34] = A[3] & B[3];
		t[35] = t[33] ^ t[32];
		t[36] = t[31] ^ t[29];
		t[37] = t[36] ^ t[27];
		t[38] = t[30] ^ t[28];
		t[39] = A[2] & B[2];
		t[40] = A[2] & B[0];
		t[41] = A[2] & B[1];
		t[42] = A[0] & B[2];
		t[43] = A[1] & B[2];
		t[44] = A[1] & B[1];
		t[45] = A[1] & B[0];
		t[46] = A[0] & B[1];
		t[47] = A[0] & B[0];
		t[48] = t[46] ^ t[45];
		t[49] = t[44] ^ t[42];
		t[50] = t[49] ^ t[40];
		t[51] = t[43] ^ t[41];
		t[52] = t[51] ^ t[34];
		t[53] = t[39] ^ t[35];
		t[54] = t[38] ^ t[21];
		t[55] = t[26] ^ t[22];
		t[56] = t[25] ^ t[8];
		t[57] = t[13] ^ t[9];
		t[58] = B[6] ^ B[9];
		t[59] = B[7] ^ B[10];
		t[60] = B[8] ^ B[11];
		t[61] = A[6] ^ A[9];
		t[62] = A[7] ^ A[10];
		t[63] = A[8] ^ A[11];
		t[64] = t[63] & t[60];
		t[65] = t[63] & t[58];
		t[66] = t[63] & t[59];
		t[67] = t[61] & t[60];
		t[68] = t[62] & t[60];
		t[69] = t[62] & t[59];
		t[70] = t[62] & t[58];
		t[71] = t[61] & t[59];
		t[72] = t[61] & t[58];
		t[73] = t[71] ^ t[70];
		t[74] = t[69] ^ t[67];
		t[75] = t[74] ^ t[65];
		t[76] = t[68] ^ t[66];
		t[77] = B[0] ^ B[3];
		t[78] = B[1] ^ B[4];
		t[79] = B[2] ^ B[5];
		t[80] = A[0] ^ A[3];
		t[81] = A[1] ^ A[4];
		t[82] = A[2] ^ A[5];
		t[83] = t[82] & t[79];
		t[84] = t[82] & t[77];
		t[85] = t[82] & t[78];
		t[86] = t[80] & t[79];
		t[87] = t[81] & t[79];
		t[88] = t[81] & t[78];
		t[89] = t[81] & t[77];
		t[90] = t[80] & t[78];
		t[91] = t[80] & t[77];
		t[92] = t[90] ^ t[89];
		t[93] = t[88] ^ t[86];
		t[94] = t[93] ^ t[84];
		t[95] = t[87] ^ t[85];
		t[96] = t[52] ^ t[47];
		t[97] = t[53] ^ t[48];
		t[98] = t[37] ^ t[50];
		t[99] = t[54] ^ t[52];
		t[100] = t[55] ^ t[53];
		t[101] = t[24] ^ t[37];
		t[102] = t[56] ^ t[54];
		t[103] = t[57] ^ t[55];
		t[104] = t[11] ^ t[24];
		t[105] = t[12] ^ t[56];
		t[106] = t[0] ^ t[57];
		t[107] = t[96] ^ t[91];
		t[108] = t[97] ^ t[92];
		t[109] = t[98] ^ t[94];
		t[110] = t[99] ^ t[95];
		t[111] = t[100] ^ t[83];
		t[112] = t[102] ^ t[72];
		t[113] = t[103] ^ t[73];
		t[114] = t[104] ^ t[75];
		t[115] = t[105] ^ t[76];
		t[116] = t[106] ^ t[64];
		t[117] = B[3] ^ B[9];
		t[118] = B[4] ^ B[10];
		t[119] = B[5] ^ B[11];
		t[120] = B[0] ^ B[6];
		t[121] = B[1] ^ B[7];
		t[122] = B[2] ^ B[8];
		t[123] = A[3] ^ A[9];
		t[124] = A[4] ^ A[10];
		t[125] = A[5] ^ A[11];
		t[126] = A[0] ^ A[6];
		t[127] = A[1] ^ A[7];
		t[128] = A[2] ^ A[8];
		t[129] = t[128] & t[122];
		t[130] = t[128] & t[120];
		t[131] = t[128] & t[121];
		t[132] = t[126] & t[122];
		t[133] = t[127] & t[122];
		t[134] = t[127] & t[121];
		t[135] = t[127] & t[120];
		t[136] = t[126] & t[121];
		t[137] = t[126] & t[120];
		t[138] = t[136] ^ t[135];
		t[139] = t[134] ^ t[132];
		t[140] = t[139] ^ t[130];
		t[141] = t[133] ^ t[131];
		t[142] = t[125] & t[119];
		t[143] = t[125] & t[117];
		t[144] = t[125] & t[118];
		t[145] = t[123] & t[119];
		t[146] = t[124] & t[119];
		t[147] = t[124] & t[118];
		t[148] = t[124] & t[117];
		t[149] = t[123] & t[118];
		t[150] = t[123] & t[117];
		t[151] = t[149] ^ t[148];
		t[152] = t[147] ^ t[145];
		t[153] = t[152] ^ t[143];
		t[154] = t[146] ^ t[144];
		t[155] = t[120] ^ t[117];
		t[156] = t[121] ^ t[118];
		t[157] = t[122] ^ t[119];
		t[158] = t[126] ^ t[123];
		t[159] = t[127] ^ t[124];
		t[160] = t[128] ^ t[125];
		t[161] = t[160] & t[157];
		t[162] = t[160] & t[155];
		t[163] = t[160] & t[156];
		t[164] = t[158] & t[157];
		t[165] = t[159] & t[157];
		t[166] = t[159] & t[156];
		t[167] = t[159] & t[155];
		t[168] = t[158] & t[156];
		t[169] = t[158] & t[155];
		t[170] = t[168] ^ t[167];
		t[171] = t[166] ^ t[164];
		t[172] = t[171] ^ t[162];
		t[173] = t[165] ^ t[163];
		t[174] = t[141] ^ t[150];
		t[175] = t[129] ^ t[151];
		t[176] = t[169] ^ t[174];
		t[177] = t[170] ^ t[175];
		t[178] = t[172] ^ t[153];
		t[179] = t[173] ^ t[154];
		t[180] = t[161] ^ t[142];
		t[181] = t[176] ^ t[137];
		t[182] = t[177] ^ t[138];
		t[183] = t[178] ^ t[140];
		t[184] = t[179] ^ t[174];
		t[185] = t[180] ^ t[175];
		t[186] = t[110] ^ t[47];
		t[187] = t[111] ^ t[48];
		t[188] = t[101] ^ t[50];
		t[189] = t[112] ^ t[107];
		t[190] = t[113] ^ t[108];
		t[191] = t[114] ^ t[109];
		t[192] = t[115] ^ t[110];
		t[193] = t[116] ^ t[111];
		t[194] = t[11] ^ t[101];
		t[195] = t[12] ^ t[112];
		t[196] = t[0] ^ t[113];
		t[197] = t[186] ^ t[137];
		t[198] = t[187] ^ t[138];
		t[199] = t[188] ^ t[140];
		t[200] = t[189] ^ t[181];
		t[201] = t[190] ^ t[182];
		t[202] = t[191] ^ t[183];
		t[203] = t[192] ^ t[184];
		t[204] = t[193] ^ t[185];
		t[205] = t[194] ^ t[153];
		t[206] = t[195] ^ t[154];
		t[207] = t[196] ^ t[142];
		sum[0] = t[47];
		sum[1] = t[48];
		sum[2] = t[50];
		sum[3] = t[107];
		sum[4] = t[108];
		sum[5] = t[109];
		sum[6] = t[197];
		sum[7] = t[198];
		sum[8] = t[199];
		sum[9] = t[200];
		sum[10] = t[201];
		sum[11] = t[202];
		sum[12] = t[203];
		sum[13] = t[204];
		sum[14] = t[205];
		sum[15] = t[206];
		sum[16] = t[207];
		sum[17] = t[114];
		sum[18] = t[115];
		sum[19] = t[116];
		sum[20] = t[11];
		sum[21] = t[12];
		sum[22] = t[0];

		for (i = 2 * OUTLEN - 2; i >= OUTLEN; i--)
		{
			sum[i - 9] ^= sum[i];
			sum[i - OUTLEN] ^= sum[i];
		}

		std::memcpy(&Output[0], &sum[0], OUTLEN * sizeof(ulong));
	}

	template<typename Array>
	inline static ulong Or(const Array &Input, size_t Degree)
	{
		ulong ret = Input[0];

		for (size_t i = 1; i < Degree; i++)
		{
			ret |= Input[i];
		}

		return ret;
	}

	template<typename Array>
	static ushort Reduce(const Array &Product, size_t Degree)
	{
		ushort ret = 0;
		int i = static_cast<int>(Degree - 1);
		std::vector<ulong> tmp(Degree);

		std::memcpy(&tmp[0], &Product[0], Degree * sizeof(ulong));

		while (i >= 0)
		{
			tmp[i] ^= (tmp[i] >> 32);
			tmp[i] ^= (tmp[i] >> 16);
			tmp[i] ^= (tmp[i] >> 8);
			tmp[i] ^= (tmp[i] >> 4);
			ret <<= 1;
			ret |= (0x6996 >> (tmp[i] & 0xF)) & 1;
			--i;
		};

		return ret;
	}

	template<typename Array>
	static void TransposeCompact64x64(Array &Output)
	{
		int i, j, s, p, idx0, idx1;
		ulong x, y;

		static const std::array<std::array<ulong, 2>, 6> mask =
		{
			{
				{ 0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL },
				{ 0x3333333333333333ULL, 0xCCCCCCCCCCCCCCCCULL },
				{ 0x0F0F0F0F0F0F0F0FULL, 0xF0F0F0F0F0F0F0F0ULL },
				{ 0x00FF00FF00FF00FFULL, 0xFF00FF00FF00FF00ULL },
				{ 0x0000FFFF0000FFFFULL, 0xFFFF0000FFFF0000ULL },
				{ 0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL }
			}
		};

		for (j = 5; j >= 0; j--)
		{
			s = 1 << j;

			for (p = 0; p < 32 / s; p++)
			{
				for (i = 0; i < s; i++)
				{
					idx0 = p * 2 * s + i;
					idx1 = p * 2 * s + i + s;
					x = (Output[idx0] & mask[j][0]) | ((Output[idx1] & mask[j][0]) << s);
					y = ((Output[idx0] & mask[j][1]) >> s) | (Output[idx1] & mask[j][1]);
					Output[idx0] = x;
					Output[idx1] = y;
				}
			}
		}
	}

	template<typename Array>
	static void Transpose8x64(Array &Output)
	{
		static const std::array<std::array<ulong, 2>, 3> mask =
		{
			{
				{ 0x5555555555555555ULL, 0xAAAAAAAAAAAAAAAAULL },
				{ 0x3333333333333333ULL, 0xCCCCCCCCCCCCCCCCULL },
				{ 0x0F0F0F0F0F0F0F0FULL, 0xF0F0F0F0F0F0F0F0ULL },
			}
		};

		ulong x;
		ulong y;

		x = (Output[0] & mask[2][0]) | ((Output[4] & mask[2][0]) << 4);
		y = ((Output[0] & mask[2][1]) >> 4) | (Output[4] & mask[2][1]);
		Output[0] = x;
		Output[4] = y;
		x = (Output[1] & mask[2][0]) | ((Output[5] & mask[2][0]) << 4);
		y = ((Output[1] & mask[2][1]) >> 4) | (Output[5] & mask[2][1]);
		Output[1] = x;
		Output[5] = y;
		x = (Output[2] & mask[2][0]) | ((Output[6] & mask[2][0]) << 4);
		y = ((Output[2] & mask[2][1]) >> 4) | (Output[6] & mask[2][1]);
		Output[2] = x;
		Output[6] = y;
		x = (Output[3] & mask[2][0]) | ((Output[7] & mask[2][0]) << 4);
		y = ((Output[3] & mask[2][1]) >> 4) | (Output[7] & mask[2][1]);
		Output[3] = x;
		Output[7] = y;
		x = (Output[0] & mask[1][0]) | ((Output[2] & mask[1][0]) << 2);
		y = ((Output[0] & mask[1][1]) >> 2) | (Output[2] & mask[1][1]);
		Output[0] = x;
		Output[2] = y;
		x = (Output[1] & mask[1][0]) | ((Output[3] & mask[1][0]) << 2);
		y = ((Output[1] & mask[1][1]) >> 2) | (Output[3] & mask[1][1]);
		Output[1] = x;
		Output[3] = y;
		x = (Output[4] & mask[1][0]) | ((Output[6] & mask[1][0]) << 2);
		y = ((Output[4] & mask[1][1]) >> 2) | (Output[6] & mask[1][1]);
		Output[4] = x;
		Output[6] = y;
		x = (Output[5] & mask[1][0]) | ((Output[7] & mask[1][0]) << 2);
		y = ((Output[5] & mask[1][1]) >> 2) | (Output[7] & mask[1][1]);
		Output[5] = x;
		Output[7] = y;
		x = (Output[0] & mask[0][0]) | ((Output[1] & mask[0][0]) << 1);
		y = ((Output[0] & mask[0][1]) >> 1) | (Output[1] & mask[0][1]);
		Output[0] = x;
		Output[1] = y;
		x = (Output[2] & mask[0][0]) | ((Output[3] & mask[0][0]) << 1);
		y = ((Output[2] & mask[0][1]) >> 1) | (Output[3] & mask[0][1]);
		Output[2] = x;
		Output[3] = y;
		x = (Output[4] & mask[0][0]) | ((Output[5] & mask[0][0]) << 1);
		y = ((Output[4] & mask[0][1]) >> 1) | (Output[5] & mask[0][1]);
		Output[4] = x;
		Output[5] = y;
		x = (Output[6] & mask[0][0]) | ((Output[7] & mask[0][0]) << 1);
		y = ((Output[6] & mask[0][1]) >> 1) | (Output[7] & mask[0][1]);
		Output[6] = x;
		Output[7] = y;
	}

	template<typename Array>
	static int Weight(Array &Input)
	{
		std::array<ulong, 8> state;
		size_t i;
		int w;

		std::memset(&state[0], 0, 64);

		for (i = 0; i < 64; i++)
		{
			AddCarry(state, Input[i]);
		}

		Transpose8x64(state);

		w = 0;

		for (i = 0; i < 64; i++)
		{
			w += reinterpret_cast<byte*>(state.data() + i);
		}

		return w;
	}
};

NAMESPACE_MCELIECEEND
#endif
