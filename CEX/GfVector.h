#ifndef _CEX_GFVECTOR_H
#define _CEX_GFVECTOR_H

#include "CexDomain.h"
#include "params.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class GfVector
{
public:

	static void vec_mul(std::vector<ulong> &H, std::vector<ulong> &F, const std::vector<ulong> &G, const size_t Dimension)
	{
		std::vector<ulong> result(2 * Dimension - 1);
		ulong t1 = F[11] & G[11];
		ulong t2 = F[11] & G[9];
		ulong t3 = F[11] & G[10];
		ulong t4 = F[9] & G[11];
		ulong t5 = F[10] & G[11];
		ulong t6 = F[10] & G[10];
		ulong t7 = F[10] & G[9];
		ulong t8 = F[9] & G[10];
		ulong t9 = F[9] & G[9];
		ulong t10 = t8 ^ t7;
		ulong t11 = t6 ^ t4;
		ulong t12 = t11 ^ t2;
		ulong t13 = t5 ^ t3;
		ulong t14 = F[8] & G[8];
		ulong t15 = F[8] & G[6];
		ulong t16 = F[8] & G[7];
		ulong t17 = F[6] & G[8];
		ulong t18 = F[7] & G[8];
		ulong t19 = F[7] & G[7];
		ulong t20 = F[7] & G[6];
		ulong t21 = F[6] & G[7];
		ulong t22 = F[6] & G[6];
		ulong t23 = t21 ^ t20;
		ulong t24 = t19 ^ t17;
		ulong t25 = t24 ^ t15;
		ulong t26 = t18 ^ t16;
		ulong t27 = F[5] & G[5];
		ulong t28 = F[5] & G[3];
		ulong t29 = F[5] & G[4];
		ulong t30 = F[3] & G[5];
		ulong t31 = F[4] & G[5];
		ulong t32 = F[4] & G[4];
		ulong t33 = F[4] & G[3];
		ulong t34 = F[3] & G[4];
		ulong t35 = F[3] & G[3];
		ulong t36 = t34 ^ t33;
		ulong t37 = t32 ^ t30;
		ulong t38 = t37 ^ t28;
		ulong t39 = t31 ^ t29;
		ulong t40 = F[2] & G[2];
		ulong t41 = F[2] & G[0];
		ulong t42 = F[2] & G[1];
		ulong t43 = F[0] & G[2];
		ulong t44 = F[1] & G[2];
		ulong t45 = F[1] & G[1];
		ulong t46 = F[1] & G[0];
		ulong t47 = F[0] & G[1];
		ulong t48 = F[0] & G[0];
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
		ulong t59 = G[6] ^ G[9];
		ulong t60 = G[7] ^ G[10];
		ulong t61 = G[8] ^ G[11];
		ulong t62 = F[6] ^ F[9];
		ulong t63 = F[7] ^ F[10];
		ulong t64 = F[8] ^ F[11];
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
		ulong t78 = G[0] ^ G[3];
		ulong t79 = G[1] ^ G[4];
		ulong t80 = G[2] ^ G[5];
		ulong t81 = F[0] ^ F[3];
		ulong t82 = F[1] ^ F[4];
		ulong t83 = F[2] ^ F[5];
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
		ulong t118 = G[3] ^ G[9];
		ulong t119 = G[4] ^ G[10];
		ulong t120 = G[5] ^ G[11];
		ulong t121 = G[0] ^ G[6];
		ulong t122 = G[1] ^ G[7];
		ulong t123 = G[2] ^ G[8];
		ulong t124 = F[3] ^ F[9];
		ulong t125 = F[4] ^ F[10];
		ulong t126 = F[5] ^ F[11];
		ulong t127 = F[0] ^ F[6];
		ulong t128 = F[1] ^ F[7];
		ulong t129 = F[2] ^ F[8];
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

		result[0] = t48;
		result[1] = t49;
		result[2] = t51;
		result[3] = t108;
		result[4] = t109;
		result[5] = t110;
		result[6] = t198;
		result[7] = t199;
		result[8] = t200;
		result[9] = t201;
		result[10] = t202;
		result[11] = t203;
		result[12] = t204;
		result[13] = t205;
		result[14] = t206;
		result[15] = t207;
		result[16] = t208;
		result[17] = t115;
		result[18] = t116;
		result[19] = t117;
		result[20] = t12;
		result[21] = t13;
		result[22] = t1;

		for (size_t i = 2 * Dimension - 2; i >= Dimension; i--)
		{
			result[i - 9] ^= result[i];
			result[i - Dimension] ^= result[i];
		}

		for (size_t i = 0; i < Dimension; i++)
			H[i] = result[i];
	}

	static void vec_sq(std::vector<ulong> &Output, std::vector<ulong> &Input, const size_t Dimension)
	{
		int i;
		ulong result[GFBITS];

		result[0] = Input[0] ^ Input[6];
		result[1] = Input[11];
		result[2] = Input[1] ^ Input[7];
		result[3] = Input[6];
		result[4] = Input[2] ^ Input[11] ^ Input[8];
		result[5] = Input[7];
		result[6] = Input[3] ^ Input[9];
		result[7] = Input[8];
		result[8] = Input[4] ^ Input[10];
		result[9] = Input[9];
		result[10] = Input[5] ^ Input[11];
		result[11] = Input[10];

		for (i = 0; i < Dimension; i++)
			Output[i] = result[i];
	}

	static void vec_copy(std::vector<ulong> &Output, const std::vector<ulong> &Input, const size_t Dimension)
	{
		for (size_t i = 0; i < Dimension; ++i)
			Output[i] = Input[i];
	}

	static ulong vec_or(const std::vector<ulong> &Input, const size_t Dimension)
	{
		int i;
		ulong ret = Input[0];

		for (i = 1; i < Dimension; i++)
			ret |= Input[i];

		return ret;
	}

	static void vec_inv(std::vector<ulong> &Output, const std::vector<ulong> &Input, const size_t Dimension)
	{
		std::vector<ulong> tmp_11(Dimension);
		std::vector<ulong> tmp_1111(Dimension);

		vec_copy(Output, Input, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_mul(tmp_11, Output, Input, Dimension);
		vec_sq(Output, tmp_11, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_mul(tmp_1111, Output, tmp_11, Dimension);
		vec_sq(Output, tmp_1111, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_mul(Output, Output, tmp_1111, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_mul(Output, Output, tmp_11, Dimension);
		vec_sq(Output, Output, Dimension);
		vec_mul(Output, Output, Input, Dimension);
		vec_sq(Output, Output, Dimension);
	}
};

NAMESPACE_MCELIECEEND
#endif