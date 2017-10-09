#ifndef _CEX_VEC_H
#define _CEX_VEC_H

#include "CexDomain.h"
#include "params.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
class vec
{
public:
	static void vec_mul(ulong *h, ulong *f, const ulong *g)
	{
		int i;

		ulong result[2 * GFBITS - 1];
		ulong t1 = f[11] & g[11];
		ulong t2 = f[11] & g[9];
		ulong t3 = f[11] & g[10];
		ulong t4 = f[9] & g[11];
		ulong t5 = f[10] & g[11];
		ulong t6 = f[10] & g[10];
		ulong t7 = f[10] & g[9];
		ulong t8 = f[9] & g[10];
		ulong t9 = f[9] & g[9];
		ulong t10 = t8 ^ t7;
		ulong t11 = t6 ^ t4;
		ulong t12 = t11 ^ t2;
		ulong t13 = t5 ^ t3;
		ulong t14 = f[8] & g[8];
		ulong t15 = f[8] & g[6];
		ulong t16 = f[8] & g[7];
		ulong t17 = f[6] & g[8];
		ulong t18 = f[7] & g[8];
		ulong t19 = f[7] & g[7];
		ulong t20 = f[7] & g[6];
		ulong t21 = f[6] & g[7];
		ulong t22 = f[6] & g[6];
		ulong t23 = t21 ^ t20;
		ulong t24 = t19 ^ t17;
		ulong t25 = t24 ^ t15;
		ulong t26 = t18 ^ t16;
		ulong t27 = f[5] & g[5];
		ulong t28 = f[5] & g[3];
		ulong t29 = f[5] & g[4];
		ulong t30 = f[3] & g[5];
		ulong t31 = f[4] & g[5];
		ulong t32 = f[4] & g[4];
		ulong t33 = f[4] & g[3];
		ulong t34 = f[3] & g[4];
		ulong t35 = f[3] & g[3];
		ulong t36 = t34 ^ t33;
		ulong t37 = t32 ^ t30;
		ulong t38 = t37 ^ t28;
		ulong t39 = t31 ^ t29;
		ulong t40 = f[2] & g[2];
		ulong t41 = f[2] & g[0];
		ulong t42 = f[2] & g[1];
		ulong t43 = f[0] & g[2];
		ulong t44 = f[1] & g[2];
		ulong t45 = f[1] & g[1];
		ulong t46 = f[1] & g[0];
		ulong t47 = f[0] & g[1];
		ulong t48 = f[0] & g[0];
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
		ulong t59 = g[6] ^ g[9];
		ulong t60 = g[7] ^ g[10];
		ulong t61 = g[8] ^ g[11];
		ulong t62 = f[6] ^ f[9];
		ulong t63 = f[7] ^ f[10];
		ulong t64 = f[8] ^ f[11];
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
		ulong t78 = g[0] ^ g[3];
		ulong t79 = g[1] ^ g[4];
		ulong t80 = g[2] ^ g[5];
		ulong t81 = f[0] ^ f[3];
		ulong t82 = f[1] ^ f[4];
		ulong t83 = f[2] ^ f[5];
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
		ulong t118 = g[3] ^ g[9];
		ulong t119 = g[4] ^ g[10];
		ulong t120 = g[5] ^ g[11];
		ulong t121 = g[0] ^ g[6];
		ulong t122 = g[1] ^ g[7];
		ulong t123 = g[2] ^ g[8];
		ulong t124 = f[3] ^ f[9];
		ulong t125 = f[4] ^ f[10];
		ulong t126 = f[5] ^ f[11];
		ulong t127 = f[0] ^ f[6];
		ulong t128 = f[1] ^ f[7];
		ulong t129 = f[2] ^ f[8];
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

		for (i = 2 * GFBITS - 2; i >= GFBITS; i--) 
		{
			result[i - 9] ^= result[i];
			result[i - GFBITS] ^= result[i];
		}

		for (i = 0; i < GFBITS; i++)
			h[i] = result[i];
	}

	static void vec_sq(ulong *out, ulong *in) 
	{
		int i;
		ulong result[GFBITS];

		result[0] = in[0] ^ in[6];
		result[1] = in[11];
		result[2] = in[1] ^ in[7];
		result[3] = in[6];
		result[4] = in[2] ^ in[11] ^ in[8];
		result[5] = in[7];
		result[6] = in[3] ^ in[9];
		result[7] = in[8];
		result[8] = in[4] ^ in[10];
		result[9] = in[9];
		result[10] = in[5] ^ in[11];
		result[11] = in[10];

		for (i = 0; i < GFBITS; i++)
			out[i] = result[i];
	}

	static void vec_copy(ulong *out, const ulong *in) 
	{
		int i;

		for (i = 0; i < GFBITS; i++)
			out[i] = in[i];
	}

	static ulong vec_or(const ulong *in) 
	{
		int i;
		ulong ret = in[0];

		for (i = 1; i < GFBITS; i++)
			ret |= in[i];

		return ret;
	}

	static void vec_inv(ulong *out, const ulong *in) 
	{
		ulong tmp_11[GFBITS];
		ulong tmp_1111[GFBITS];

		vec_copy(out, in);

		vec_sq(out, out);
		vec_mul(tmp_11, out, in); // 11

		vec_sq(out, tmp_11);
		vec_sq(out, out);
		vec_mul(tmp_1111, out, tmp_11); // 1111

		vec_sq(out, tmp_1111);
		vec_sq(out, out);
		vec_sq(out, out);
		vec_sq(out, out);
		vec_mul(out, out, tmp_1111); // 11111111

		vec_sq(out, out);
		vec_sq(out, out);
		vec_mul(out, out, tmp_11); // 1111111111

		vec_sq(out, out);
		vec_mul(out, out, in); // 11111111111

		vec_sq(out, out); // 111111111110
	}
};

NAMESPACE_MCELIECEEND
#endif