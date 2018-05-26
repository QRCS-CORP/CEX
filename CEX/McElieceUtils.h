// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
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
class McElieceUtils
{
public:

	//~~~Public Functions~~~//

	static ushort Diff(ushort A, ushort B);

	static ushort Invert(ushort X, const size_t Degree);

	static ulong MaskNonZero64(ushort A);

	static ulong MaskLeq64(ushort A, ushort B);

	static ushort Multiply(ushort X, ushort Y, const size_t Degree);

	static ushort Square(ushort X, const size_t Degree);

	//~~~Templates~~~//

	template<typename Array>
	inline static void Add(Array &X, Array &Y)
	{
		for (size_t i = 0; i < X.size(); i++)
		{
			X[i] ^= Y[i];
		}
	}

	template<typename Array>
	inline static void Add(Array &Output, Array &X, Array &Y)
	{
		for (size_t i = 0; i < Output.size(); i++)
		{
			Output[i] = X[i] ^ Y[i];
		}
	}

	template<typename Array>
	inline static void AddCarry(Array &A, ulong N)
	{
		ulong carry = N;
		ulong t;

		for (size_t i = 0; i < 8; i++)
		{
			t = A[i] ^ carry;
			carry = A[i] & carry;
			A[i] = t;
		}
	}

	template<typename ArrayA, typename ArrayB>
	static void BenesCompact(ArrayA &Received, ArrayB &Condition, int Reverse)
	{
		size_t condPos;
		int inc, low;

		if (Reverse == 0)
		{
			inc = 32;
			condPos = 0;
		}
		else
		{
			inc = -32;
			condPos = 704;
		}

		for (low = 0; low <= 5; low++)
		{
			BenesHelp(Received, Condition, condPos, low);
			condPos += inc;
		}

		TransposeCompact64x64(Received);

		for (low = 0; low <= 5; low++)
		{
			BenesHelp(Received, Condition, condPos, low);
			condPos += inc;
		}

		for (low = 4; low >= 0; low--)
		{
			BenesHelp(Received, Condition, condPos, low);
			condPos += inc;
		}

		TransposeCompact64x64(Received);

		for (low = 5; low >= 0; low--)
		{
			BenesHelp(Received, Condition, condPos, low);
			condPos += inc;
		}
	}

	template<typename ArrayA, typename ArrayB>
	static void BenesHelp(ArrayA &Received, ArrayB &Condition, size_t CondPos, int Low)
	{
		int i, j, x, y;
		int high = 5 - Low;
		ulong diff;

		for (j = 0; j < (1 << Low); j++)
		{
			x = (0 << Low) + j;
			y = (1 << Low) + j;

			for (i = 0; i < (1 << high); i++)
			{
				diff = Received[x] ^ Received[y];
				diff &= Condition[CondPos];
				++CondPos;
				Received[x] ^= diff;
				Received[y] ^= diff;
				x += (1 << (Low + 1));
				y += (1 << (Low + 1));
			}
		}
	}

	template<typename ArrayA, typename ArrayB>
	inline static void CMov(ArrayB &Input, ArrayA &Output, ulong Mask)
	{
		for (size_t i = 0; i < Output.size(); i++)
		{
			Output[i] = (Input[i] & Mask) | (Output[i] & ~Mask);
		}
	}

	template<typename ArrayA, typename ArrayB>
	inline static void Copy(const ArrayB &Input, ArrayA &Output)
	{
		for (size_t i = 0; i < Output.size(); i++)
		{
			Output[i] = Input[i];
		}
	}

	template<typename Array>
	inline static void Insert(Array &Output, const ushort N)
	{
		for (size_t i = 0; i < Output.size(); i++)
		{
			Output[i] = (N >> i) & 1;
			Output[i] = ~Output[i] + 1;
		}
	}

	template<typename ArrayA, typename ArrayB>
	static void Multiply(ArrayA &Output, ArrayA &A, const ArrayB &B)
	{
		ulong t1 = A[11] & B[11];
		ulong t2 = A[11] & B[9];
		ulong t3 = A[11] & B[10];
		ulong t4 = A[9] & B[11];
		ulong t5 = A[10] & B[11];
		ulong t6 = A[10] & B[10];
		ulong t7 = A[10] & B[9];
		ulong t8 = A[9] & B[10];
		ulong t9 = A[9] & B[9];
		ulong t10 = t8 ^ t7;
		ulong t11 = t6 ^ t4;
		ulong t12 = t11 ^ t2;
		ulong t13 = t5 ^ t3;
		ulong t14 = A[8] & B[8];
		ulong t15 = A[8] & B[6];
		ulong t16 = A[8] & B[7];
		ulong t17 = A[6] & B[8];
		ulong t18 = A[7] & B[8];
		ulong t19 = A[7] & B[7];
		ulong t20 = A[7] & B[6];
		ulong t21 = A[6] & B[7];
		ulong t22 = A[6] & B[6];
		ulong t23 = t21 ^ t20;
		ulong t24 = t19 ^ t17;
		ulong t25 = t24 ^ t15;
		ulong t26 = t18 ^ t16;
		ulong t27 = A[5] & B[5];
		ulong t28 = A[5] & B[3];
		ulong t29 = A[5] & B[4];
		ulong t30 = A[3] & B[5];
		ulong t31 = A[4] & B[5];
		ulong t32 = A[4] & B[4];
		ulong t33 = A[4] & B[3];
		ulong t34 = A[3] & B[4];
		ulong t35 = A[3] & B[3];
		ulong t36 = t34 ^ t33;
		ulong t37 = t32 ^ t30;
		ulong t38 = t37 ^ t28;
		ulong t39 = t31 ^ t29;
		ulong t40 = A[2] & B[2];
		ulong t41 = A[2] & B[0];
		ulong t42 = A[2] & B[1];
		ulong t43 = A[0] & B[2];
		ulong t44 = A[1] & B[2];
		ulong t45 = A[1] & B[1];
		ulong t46 = A[1] & B[0];
		ulong t47 = A[0] & B[1];
		ulong t48 = A[0] & B[0];
		ulong t49 = t47 ^ t46;
		ulong t50 = t45 ^ t43;
		ulong t51 = t50 ^ t41;
		ulong t52 = t44 ^ t42;
		ulong t53 = t52 ^ t35;
		ulong t54 = t40 ^ t36;
		ulong t55 = t39 ^ t22;
		ulong t56 = t27 ^ t23;
		ulong t57 = t26 ^ t9;
		ulong t58 = t14 ^ t10;
		ulong t59 = B[6] ^ B[9];
		ulong t60 = B[7] ^ B[10];
		ulong t61 = B[8] ^ B[11];
		ulong t62 = A[6] ^ A[9];
		ulong t63 = A[7] ^ A[10];
		ulong t64 = A[8] ^ A[11];
		ulong t65 = t64 & t61;
		ulong t66 = t64 & t59;
		ulong t67 = t64 & t60;
		ulong t68 = t62 & t61;
		ulong t69 = t63 & t61;
		ulong t70 = t63 & t60;
		ulong t71 = t63 & t59;
		ulong t72 = t62 & t60;
		ulong t73 = t62 & t59;
		ulong t74 = t72 ^ t71;
		ulong t75 = t70 ^ t68;
		ulong t76 = t75 ^ t66;
		ulong t77 = t69 ^ t67;
		ulong t78 = B[0] ^ B[3];
		ulong t79 = B[1] ^ B[4];
		ulong t80 = B[2] ^ B[5];
		ulong t81 = A[0] ^ A[3];
		ulong t82 = A[1] ^ A[4];
		ulong t83 = A[2] ^ A[5];
		ulong t84 = t83 & t80;
		ulong t85 = t83 & t78;
		ulong t86 = t83 & t79;
		ulong t87 = t81 & t80;
		ulong t88 = t82 & t80;
		ulong t89 = t82 & t79;
		ulong t90 = t82 & t78;
		ulong t91 = t81 & t79;
		ulong t92 = t81 & t78;
		ulong t93 = t91 ^ t90;
		ulong t94 = t89 ^ t87;
		ulong t95 = t94 ^ t85;
		ulong t96 = t88 ^ t86;
		ulong t97 = t53 ^ t48;
		ulong t98 = t54 ^ t49;
		ulong t99 = t38 ^ t51;
		ulong t100 = t55 ^ t53;
		ulong t101 = t56 ^ t54;
		ulong t102 = t25 ^ t38;
		ulong t103 = t57 ^ t55;
		ulong t104 = t58 ^ t56;
		ulong t105 = t12 ^ t25;
		ulong t106 = t13 ^ t57;
		ulong t107 = t1 ^ t58;
		ulong t108 = t97 ^ t92;
		ulong t109 = t98 ^ t93;
		ulong t110 = t99 ^ t95;
		ulong t111 = t100 ^ t96;
		ulong t112 = t101 ^ t84;
		ulong t113 = t103 ^ t73;
		ulong t114 = t104 ^ t74;
		ulong t115 = t105 ^ t76;
		ulong t116 = t106 ^ t77;
		ulong t117 = t107 ^ t65;
		ulong t118 = B[3] ^ B[9];
		ulong t119 = B[4] ^ B[10];
		ulong t120 = B[5] ^ B[11];
		ulong t121 = B[0] ^ B[6];
		ulong t122 = B[1] ^ B[7];
		ulong t123 = B[2] ^ B[8];
		ulong t124 = A[3] ^ A[9];
		ulong t125 = A[4] ^ A[10];
		ulong t126 = A[5] ^ A[11];
		ulong t127 = A[0] ^ A[6];
		ulong t128 = A[1] ^ A[7];
		ulong t129 = A[2] ^ A[8];
		ulong t130 = t129 & t123;
		ulong t131 = t129 & t121;
		ulong t132 = t129 & t122;
		ulong t133 = t127 & t123;
		ulong t134 = t128 & t123;
		ulong t135 = t128 & t122;
		ulong t136 = t128 & t121;
		ulong t137 = t127 & t122;
		ulong t138 = t127 & t121;
		ulong t139 = t137 ^ t136;
		ulong t140 = t135 ^ t133;
		ulong t141 = t140 ^ t131;
		ulong t142 = t134 ^ t132;
		ulong t143 = t126 & t120;
		ulong t144 = t126 & t118;
		ulong t145 = t126 & t119;
		ulong t146 = t124 & t120;
		ulong t147 = t125 & t120;
		ulong t148 = t125 & t119;
		ulong t149 = t125 & t118;
		ulong t150 = t124 & t119;
		ulong t151 = t124 & t118;
		ulong t152 = t150 ^ t149;
		ulong t153 = t148 ^ t146;
		ulong t154 = t153 ^ t144;
		ulong t155 = t147 ^ t145;
		ulong t156 = t121 ^ t118;
		ulong t157 = t122 ^ t119;
		ulong t158 = t123 ^ t120;
		ulong t159 = t127 ^ t124;
		ulong t160 = t128 ^ t125;
		ulong t161 = t129 ^ t126;
		ulong t162 = t161 & t158;
		ulong t163 = t161 & t156;
		ulong t164 = t161 & t157;
		ulong t165 = t159 & t158;
		ulong t166 = t160 & t158;
		ulong t167 = t160 & t157;
		ulong t168 = t160 & t156;
		ulong t169 = t159 & t157;
		ulong t170 = t159 & t156;
		ulong t171 = t169 ^ t168;
		ulong t172 = t167 ^ t165;
		ulong t173 = t172 ^ t163;
		ulong t174 = t166 ^ t164;
		ulong t175 = t142 ^ t151;
		ulong t176 = t130 ^ t152;
		ulong t177 = t170 ^ t175;
		ulong t178 = t171 ^ t176;
		ulong t179 = t173 ^ t154;
		ulong t180 = t174 ^ t155;
		ulong t181 = t162 ^ t143;
		ulong t182 = t177 ^ t138;
		ulong t183 = t178 ^ t139;
		ulong t184 = t179 ^ t141;
		ulong t185 = t180 ^ t175;
		ulong t186 = t181 ^ t176;
		ulong t187 = t111 ^ t48;
		ulong t188 = t112 ^ t49;
		ulong t189 = t102 ^ t51;
		ulong t190 = t113 ^ t108;
		ulong t191 = t114 ^ t109;
		ulong t192 = t115 ^ t110;
		ulong t193 = t116 ^ t111;
		ulong t194 = t117 ^ t112;
		ulong t195 = t12 ^ t102;
		ulong t196 = t13 ^ t113;
		ulong t197 = t1 ^ t114;
		ulong t198 = t187 ^ t138;
		ulong t199 = t188 ^ t139;
		ulong t200 = t189 ^ t141;
		ulong t201 = t190 ^ t182;
		ulong t202 = t191 ^ t183;
		ulong t203 = t192 ^ t184;
		ulong t204 = t193 ^ t185;
		ulong t205 = t194 ^ t186;
		ulong t206 = t195 ^ t154;
		ulong t207 = t196 ^ t155;
		ulong t208 = t197 ^ t143;

		const size_t OUTLEN = Output.size();
		std::vector<ulong> sum(2 * OUTLEN - 1);
		sum[0] = t48;
		sum[1] = t49;
		sum[2] = t51;
		sum[3] = t108;
		sum[4] = t109;
		sum[5] = t110;
		sum[6] = t198;
		sum[7] = t199;
		sum[8] = t200;
		sum[9] = t201;
		sum[10] = t202;
		sum[11] = t203;
		sum[12] = t204;
		sum[13] = t205;
		sum[14] = t206;
		sum[15] = t207;
		sum[16] = t208;
		sum[17] = t115;
		sum[18] = t116;
		sum[19] = t117;
		sum[20] = t12;
		sum[21] = t13;
		sum[22] = t1;

		for (size_t i = 2 * OUTLEN - 2; i >= OUTLEN; i--)
		{
			sum[i - 9] ^= sum[i];
			sum[i - OUTLEN] ^= sum[i];
		}

		std::memcpy(&Output[0], &sum[0], OUTLEN * sizeof(ulong));
	}

	template<typename Array>
	inline static ulong Or(const Array &Input, const size_t Degree)
	{
		ulong ret = Input[0];

		for (size_t i = 1; i < Degree; i++)
		{
			ret |= Input[i];
		}

		return ret;
	}

	template<typename Array>
	static ushort Reduce(Array &Product, const size_t Degree)
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

		ulong x, y;

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
	static int Weight(Array &A)
	{
		size_t i;
		std::array<ulong, 8> state;
		std::memset(&state[0], 0, 64);

		for (i = 0; i < 64; i++)
		{
			AddCarry(state, A[i]);
		}

		Transpose8x64(state);

		int w = 0;
		for (i = 0; i < 64; i++)
		{
			w += ((byte*)state.data())[i];
		}

		return w;
	}
};

NAMESPACE_MCELIECEEND
#endif
