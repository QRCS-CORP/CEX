#ifndef _CEX_FFTM12T62_H
#define _CEX_FFTM12T62_H

#include "CexDomain.h"
//#include "GF.h"
#include "GfVector.h"
#include "IPrng.h"
#include "IntUtils.h"
#include "MemUtils.h"

NAMESPACE_MCELIECE

class FFTM12T62
{
private:

	#define GFBITS 12
	#define SYS_T 62
	#define PK_NROWS (SYS_T * GFBITS)
	#define PK_NCOLS ((1 << GFBITS) - SYS_T * GFBITS)	// 3352 (1 << M) - (M * T)
	#define IRR_BYTES (GFBITS * 8)				// 96
	#define COND_BYTES (736 * 8)			// 5888 (736? PK_NROWS + 8) * 8
	#define SYND_BYTES (PK_NROWS / 8)		// 93

public:

	#define CRYPTO_SECRETKEYBYTES (IRR_BYTES + COND_BYTES)	// 5984 (IRR_BYTES + COND_BYTES)
	#define CRYPTO_PUBLICKEYBYTES 311736	// 311736
	#define CRYPTO_BYTES 109				// 109

private:

	static const std::vector<std::vector<ulong>> ButterflyConsts;
	static const std::vector<byte> ButterflyReverse;
	static const std::vector<std::vector<ulong>> GfPoints;
	static const std::vector<std::vector<ulong>> RadixMask;
	static const std::vector<std::vector<ulong>> RadixScalar;
	static const std::vector<std::vector<ulong>> RadixTrMask;
	static const std::vector<std::vector<std::vector<ulong>>> RadixTrScalar;

	/////// vec.c

	static void vec_mul(uint64_t *h, uint64_t *f, const uint64_t *g)
	{
		int i;
		uint64_t result[2 * GFBITS - 1];

		uint64_t t1 = f[11] & g[11];
		uint64_t t2 = f[11] & g[9];
		uint64_t t3 = f[11] & g[10];
		uint64_t t4 = f[9] & g[11];
		uint64_t t5 = f[10] & g[11];
		uint64_t t6 = f[10] & g[10];
		uint64_t t7 = f[10] & g[9];
		uint64_t t8 = f[9] & g[10];
		uint64_t t9 = f[9] & g[9];
		uint64_t t10 = t8 ^ t7;
		uint64_t t11 = t6 ^ t4;
		uint64_t t12 = t11 ^ t2;
		uint64_t t13 = t5 ^ t3;
		uint64_t t14 = f[8] & g[8];
		uint64_t t15 = f[8] & g[6];
		uint64_t t16 = f[8] & g[7];
		uint64_t t17 = f[6] & g[8];
		uint64_t t18 = f[7] & g[8];
		uint64_t t19 = f[7] & g[7];
		uint64_t t20 = f[7] & g[6];
		uint64_t t21 = f[6] & g[7];
		uint64_t t22 = f[6] & g[6];
		uint64_t t23 = t21 ^ t20;
		uint64_t t24 = t19 ^ t17;
		uint64_t t25 = t24 ^ t15;
		uint64_t t26 = t18 ^ t16;
		uint64_t t27 = f[5] & g[5];
		uint64_t t28 = f[5] & g[3];
		uint64_t t29 = f[5] & g[4];
		uint64_t t30 = f[3] & g[5];
		uint64_t t31 = f[4] & g[5];
		uint64_t t32 = f[4] & g[4];
		uint64_t t33 = f[4] & g[3];
		uint64_t t34 = f[3] & g[4];
		uint64_t t35 = f[3] & g[3];
		uint64_t t36 = t34 ^ t33;
		uint64_t t37 = t32 ^ t30;
		uint64_t t38 = t37 ^ t28;
		uint64_t t39 = t31 ^ t29;
		uint64_t t40 = f[2] & g[2];
		uint64_t t41 = f[2] & g[0];
		uint64_t t42 = f[2] & g[1];
		uint64_t t43 = f[0] & g[2];
		uint64_t t44 = f[1] & g[2];
		uint64_t t45 = f[1] & g[1];
		uint64_t t46 = f[1] & g[0];
		uint64_t t47 = f[0] & g[1];
		uint64_t t48 = f[0] & g[0];
		uint64_t t49 = t47 ^ t46;
		uint64_t t50 = t45 ^ t43;
		uint64_t t51 = t50 ^ t41;
		uint64_t t52 = t44 ^ t42;
		uint64_t t53 = t52 ^ t35;
		uint64_t t54 = t40 ^ t36;
		uint64_t t55 = t39 ^ t22;
		uint64_t t56 = t27 ^ t23;
		uint64_t t57 = t26 ^ t9;
		uint64_t t58 = t14 ^ t10;
		uint64_t t59 = g[6] ^ g[9];
		uint64_t t60 = g[7] ^ g[10];
		uint64_t t61 = g[8] ^ g[11];
		uint64_t t62 = f[6] ^ f[9];
		uint64_t t63 = f[7] ^ f[10];
		uint64_t t64 = f[8] ^ f[11];
		uint64_t t65 = t64 & t61;
		uint64_t t66 = t64 & t59;
		uint64_t t67 = t64 & t60;
		uint64_t t68 = t62 & t61;
		uint64_t t69 = t63 & t61;
		uint64_t t70 = t63 & t60;
		uint64_t t71 = t63 & t59;
		uint64_t t72 = t62 & t60;
		uint64_t t73 = t62 & t59;
		uint64_t t74 = t72 ^ t71;
		uint64_t t75 = t70 ^ t68;
		uint64_t t76 = t75 ^ t66;
		uint64_t t77 = t69 ^ t67;
		uint64_t t78 = g[0] ^ g[3];
		uint64_t t79 = g[1] ^ g[4];
		uint64_t t80 = g[2] ^ g[5];
		uint64_t t81 = f[0] ^ f[3];
		uint64_t t82 = f[1] ^ f[4];
		uint64_t t83 = f[2] ^ f[5];
		uint64_t t84 = t83 & t80;
		uint64_t t85 = t83 & t78;
		uint64_t t86 = t83 & t79;
		uint64_t t87 = t81 & t80;
		uint64_t t88 = t82 & t80;
		uint64_t t89 = t82 & t79;
		uint64_t t90 = t82 & t78;
		uint64_t t91 = t81 & t79;
		uint64_t t92 = t81 & t78;
		uint64_t t93 = t91 ^ t90;
		uint64_t t94 = t89 ^ t87;
		uint64_t t95 = t94 ^ t85;
		uint64_t t96 = t88 ^ t86;
		uint64_t t97 = t53 ^ t48;
		uint64_t t98 = t54 ^ t49;
		uint64_t t99 = t38 ^ t51;
		uint64_t t100 = t55 ^ t53;
		uint64_t t101 = t56 ^ t54;
		uint64_t t102 = t25 ^ t38;
		uint64_t t103 = t57 ^ t55;
		uint64_t t104 = t58 ^ t56;
		uint64_t t105 = t12 ^ t25;
		uint64_t t106 = t13 ^ t57;
		uint64_t t107 = t1 ^ t58;
		uint64_t t108 = t97 ^ t92;
		uint64_t t109 = t98 ^ t93;
		uint64_t t110 = t99 ^ t95;
		uint64_t t111 = t100 ^ t96;
		uint64_t t112 = t101 ^ t84;
		uint64_t t113 = t103 ^ t73;
		uint64_t t114 = t104 ^ t74;
		uint64_t t115 = t105 ^ t76;
		uint64_t t116 = t106 ^ t77;
		uint64_t t117 = t107 ^ t65;
		uint64_t t118 = g[3] ^ g[9];
		uint64_t t119 = g[4] ^ g[10];
		uint64_t t120 = g[5] ^ g[11];
		uint64_t t121 = g[0] ^ g[6];
		uint64_t t122 = g[1] ^ g[7];
		uint64_t t123 = g[2] ^ g[8];
		uint64_t t124 = f[3] ^ f[9];
		uint64_t t125 = f[4] ^ f[10];
		uint64_t t126 = f[5] ^ f[11];
		uint64_t t127 = f[0] ^ f[6];
		uint64_t t128 = f[1] ^ f[7];
		uint64_t t129 = f[2] ^ f[8];
		uint64_t t130 = t129 & t123;
		uint64_t t131 = t129 & t121;
		uint64_t t132 = t129 & t122;
		uint64_t t133 = t127 & t123;
		uint64_t t134 = t128 & t123;
		uint64_t t135 = t128 & t122;
		uint64_t t136 = t128 & t121;
		uint64_t t137 = t127 & t122;
		uint64_t t138 = t127 & t121;
		uint64_t t139 = t137 ^ t136;
		uint64_t t140 = t135 ^ t133;
		uint64_t t141 = t140 ^ t131;
		uint64_t t142 = t134 ^ t132;
		uint64_t t143 = t126 & t120;
		uint64_t t144 = t126 & t118;
		uint64_t t145 = t126 & t119;
		uint64_t t146 = t124 & t120;
		uint64_t t147 = t125 & t120;
		uint64_t t148 = t125 & t119;
		uint64_t t149 = t125 & t118;
		uint64_t t150 = t124 & t119;
		uint64_t t151 = t124 & t118;
		uint64_t t152 = t150 ^ t149;
		uint64_t t153 = t148 ^ t146;
		uint64_t t154 = t153 ^ t144;
		uint64_t t155 = t147 ^ t145;
		uint64_t t156 = t121 ^ t118;
		uint64_t t157 = t122 ^ t119;
		uint64_t t158 = t123 ^ t120;
		uint64_t t159 = t127 ^ t124;
		uint64_t t160 = t128 ^ t125;
		uint64_t t161 = t129 ^ t126;
		uint64_t t162 = t161 & t158;
		uint64_t t163 = t161 & t156;
		uint64_t t164 = t161 & t157;
		uint64_t t165 = t159 & t158;
		uint64_t t166 = t160 & t158;
		uint64_t t167 = t160 & t157;
		uint64_t t168 = t160 & t156;
		uint64_t t169 = t159 & t157;
		uint64_t t170 = t159 & t156;
		uint64_t t171 = t169 ^ t168;
		uint64_t t172 = t167 ^ t165;
		uint64_t t173 = t172 ^ t163;
		uint64_t t174 = t166 ^ t164;
		uint64_t t175 = t142 ^ t151;
		uint64_t t176 = t130 ^ t152;
		uint64_t t177 = t170 ^ t175;
		uint64_t t178 = t171 ^ t176;
		uint64_t t179 = t173 ^ t154;
		uint64_t t180 = t174 ^ t155;
		uint64_t t181 = t162 ^ t143;
		uint64_t t182 = t177 ^ t138;
		uint64_t t183 = t178 ^ t139;
		uint64_t t184 = t179 ^ t141;
		uint64_t t185 = t180 ^ t175;
		uint64_t t186 = t181 ^ t176;
		uint64_t t187 = t111 ^ t48;
		uint64_t t188 = t112 ^ t49;
		uint64_t t189 = t102 ^ t51;
		uint64_t t190 = t113 ^ t108;
		uint64_t t191 = t114 ^ t109;
		uint64_t t192 = t115 ^ t110;
		uint64_t t193 = t116 ^ t111;
		uint64_t t194 = t117 ^ t112;
		uint64_t t195 = t12 ^ t102;
		uint64_t t196 = t13 ^ t113;
		uint64_t t197 = t1 ^ t114;
		uint64_t t198 = t187 ^ t138;
		uint64_t t199 = t188 ^ t139;
		uint64_t t200 = t189 ^ t141;
		uint64_t t201 = t190 ^ t182;
		uint64_t t202 = t191 ^ t183;
		uint64_t t203 = t192 ^ t184;
		uint64_t t204 = t193 ^ t185;
		uint64_t t205 = t194 ^ t186;
		uint64_t t206 = t195 ^ t154;
		uint64_t t207 = t196 ^ t155;
		uint64_t t208 = t197 ^ t143;

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

		//

		for (i = 2 * GFBITS - 2; i >= GFBITS; i--) 
		{
			result[i - 9] ^= result[i];
			result[i - GFBITS] ^= result[i];
		}

		//

		for (i = 0; i < GFBITS; i++)
			h[i] = result[i];
	}

	static void vec_sq(uint64_t *out, uint64_t *in)
	{
		int i;
		uint64_t result[GFBITS];

		//

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

		//

		for (i = 0; i < GFBITS; i++)
			out[i] = result[i];
	}

	static void vec_copy(uint64_t *out, const uint64_t *in) 
	{
		int i;

		for (i = 0; i < GFBITS; i++)
			out[i] = in[i];
	}

	static uint64_t vec_or(const uint64_t *in) 
	{
		int i;
		uint64_t ret = in[0];

		for (i = 1; i < GFBITS; i++)
			ret |= in[i];

		return ret;
	}

	static void vec_inv(uint64_t *out, const uint64_t *in) 
	{
		uint64_t tmp_11[GFBITS];
		uint64_t tmp_1111[GFBITS];

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

	/////// gf.c

	typedef uint16_t gf;

	static gf gf_mul(gf in0, gf in1)
	{
		int i;

		uint32_t tmp;
		uint32_t t0;
		uint32_t t1;
		uint32_t t;

		t0 = in0;
		t1 = in1;

		tmp = t0 * (t1 & 1);

		for (i = 1; i < GFBITS; i++)
			tmp ^= (t0 * (t1 & (1 << i)));

		t = tmp & 0x7FC000;
		tmp ^= t >> 9;
		tmp ^= t >> 12;

		t = tmp & 0x3000;
		tmp ^= t >> 9;
		tmp ^= t >> 12;

		return tmp & ((1 << GFBITS) - 1);
	}

	static gf gf_sq(gf in)
	{
		const uint32_t B[] = { 0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF };

		uint32_t x = in;
		uint32_t t;

		x = (x | (x << 8)) & B[3];
		x = (x | (x << 4)) & B[2];
		x = (x | (x << 2)) & B[1];
		x = (x | (x << 1)) & B[0];

		t = x & 0x7FC000;
		x ^= t >> 9;
		x ^= t >> 12;

		t = x & 0x3000;
		x ^= t >> 9;
		x ^= t >> 12;

		return x & ((1 << GFBITS) - 1);
	}

	static gf gf_inv(gf in)
	{
		gf tmp_11;
		gf tmp_1111;

		gf out = in;

		out = gf_sq(out);
		tmp_11 = gf_mul(out, in); // 11

		out = gf_sq(tmp_11);
		out = gf_sq(out);
		tmp_1111 = gf_mul(out, tmp_11); // 1111

		out = gf_sq(tmp_1111);
		out = gf_sq(out);
		out = gf_sq(out);
		out = gf_sq(out);
		out = gf_mul(out, tmp_1111); // 11111111

		out = gf_sq(out);
		out = gf_sq(out);
		out = gf_mul(out, tmp_11); // 1111111111

		out = gf_sq(out);
		out = gf_mul(out, in); // 11111111111

		return gf_sq(out); // 111111111110
	}

	static gf gf_diff(gf a, gf b)
	{
		uint32_t t = (uint32_t)(a ^ b);

		t = ((t - 1) >> 20) ^ 0xFFF;

		return (gf)t;
	}

	///////////////////////////////////////////////////////////

	static void GF_mul(gf *out, gf *in0, gf *in1)
	{
		int i, j;

		gf tmp[123];

		for (i = 0; i < 123; i++)
			tmp[i] = 0;

		for (i = 0; i < 62; i++)
			for (j = 0; j < 62; j++)
				tmp[i + j] ^= gf_mul(in0[i], in1[j]);

		//

		for (i = 122; i >= 62; i--) {
			tmp[i - 55] ^= gf_mul(tmp[i], (gf)1763);
			tmp[i - 61] ^= gf_mul(tmp[i], (gf)1722);
			tmp[i - 62] ^= gf_mul(tmp[i], (gf)4033);
		}

		for (i = 0; i < 62; i++)
			out[i] = tmp[i];
	}


	/////// bm.c Berlekamp Massey

	typedef uint16_t gf;

	static void into_vec(int64_t *out, gf in) 
	{
		for (size_t i = 0; i < GFBITS; i++) 
		{
			out[i] = (in >> i) & 1;
			out[i] = -out[i];
		}
	}

	static gf vec_reduce(uint64_t *prod) 
	{
		int i;

		uint64_t tmp[GFBITS];
		gf ret = 0;

		for (i = 0; i < GFBITS; i++)
			tmp[i] = prod[i];
		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 32);
		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 16);
		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 8);
		for (i = GFBITS - 1; i >= 0; i--)
			tmp[i] ^= (tmp[i] >> 4);
		for (i = GFBITS - 1; i >= 0; i--)
		{
			ret <<= 1;
			ret |= (0x6996 >> (tmp[i] & 0xF)) & 1;
		}

		return ret;
	}

	static uint64_t mask_nonzero_64bit(gf a) 
	{
		uint64_t ret = a;
		ret -= 1;
		ret >>= 63;
		ret -= 1;

		return ret;
	}

	static uint64_t mask_leq_64bit(uint16_t a, uint16_t b) 
	{
		uint64_t a_tmp = a;
		uint64_t b_tmp = b;
		uint64_t ret = b_tmp - a_tmp;
		ret >>= 63;
		ret -= 1;

		return ret;
	}

	static void vec_cmov(uint64_t *out, uint64_t *in, uint64_t mask) 
	{
		for (size_t i = 0; i < GFBITS; i++)
			out[i] = (in[i] & mask) | (out[i] & ~mask);
	}

	static void bm(uint64_t out[GFBITS], uint64_t in[][GFBITS]) 
	{
		uint16_t i;
		uint16_t N, L;

		uint64_t C[GFBITS], B[GFBITS], prod[GFBITS];
		int64_t in_tmp[GFBITS], r_vec[GFBITS], C_tmp[GFBITS];

		uint64_t mask_nz, mask_leq;
		uint16_t mask_16b;

		gf d, b, b_inv, r;

		// init

		C[0] = 1;
		C[0] <<= 63;
		B[0] = 1;
		B[0] <<= 62;

		for (i = 1; i < GFBITS; i++)
			B[i] = C[i] = 0;

		b = 1;
		L = 0;

		//

		for (N = 0; N < SYS_T * 2; N++) 
		{
			// computing d

			if (N < 64)
				for (i = 0; i < GFBITS; i++)
					in_tmp[i] = in[0][i] << (63 - N);

			else
				for (i = 0; i < GFBITS; i++)
					in_tmp[i] = (in[0][i] >> (N - 63)) | (in[1][i] << (127 - N));

			vec_mul(prod, C, (uint64_t*)in_tmp);
			d = vec_reduce(prod);

			// 3 cases

			b_inv = gf_inv(b);
			r = gf_mul(d, b_inv);
			into_vec(r_vec, r);
			vec_mul((uint64_t*)C_tmp, (uint64_t*)r_vec, B);

			for (i = 0; i < GFBITS; i++)
				C_tmp[i] ^= C[i];

			mask_nz = mask_nonzero_64bit(d);
			mask_leq = mask_leq_64bit(L * 2, N);
			mask_16b = (mask_nz & mask_leq) & 0xFFFF;

			vec_cmov(B, C, mask_nz & mask_leq);
			vec_copy(C, (uint64_t*)C_tmp);

			b = (d & mask_16b) | (b & ~mask_16b);
			L = ((N + 1 - L) & mask_16b) | (L & ~mask_16b);

			for (i = 0; i < GFBITS; i++)
				B[i] >>= 1;
		}

		vec_copy(out, C);

		for (i = 0; i < GFBITS; i++)
			out[i] >>= 64 - (SYS_T + 1);
	}

	/////// transpose.c

	static void transpose_64x64_compact(uint64_t *out, uint64_t *in) 
	{
		int i, j, s, p, idx0, idx1;
		uint64_t x, y;

		const uint64_t mask[6][2] = 
		{
			{ 0X5555555555555555, 0XAAAAAAAAAAAAAAAA },
			{ 0X3333333333333333, 0XCCCCCCCCCCCCCCCC },
			{ 0X0F0F0F0F0F0F0F0F, 0XF0F0F0F0F0F0F0F0 },
			{ 0X00FF00FF00FF00FF, 0XFF00FF00FF00FF00 },
			{ 0X0000FFFF0000FFFF, 0XFFFF0000FFFF0000 },
			{ 0X00000000FFFFFFFF, 0XFFFFFFFF00000000 } 
		};

		//

		for (i = 0; i < 64; i++)
			out[i] = in[i];

		for (j = 5; j >= 0; j--) 
		{
			s = 1 << j;

			for (p = 0; p < 32 / s; p++) 
			{
				for (i = 0; i < s; i++) 
				{
					idx0 = p * 2 * s + i;
					idx1 = p * 2 * s + i + s;

					x = (out[idx0] & mask[j][0]) | ((out[idx1] & mask[j][0]) << s);
					y = ((out[idx0] & mask[j][1]) >> s) | (out[idx1] & mask[j][1]);

					out[idx0] = x;
					out[idx1] = y;
				}
			}
		}
	}

	static void transpose_8x64(uint64_t *in) 
	{
		const uint64_t mask[3][2] = 
		{
			{ 0X5555555555555555, 0XAAAAAAAAAAAAAAAA },
			{ 0X3333333333333333, 0XCCCCCCCCCCCCCCCC },
			{ 0X0F0F0F0F0F0F0F0F, 0XF0F0F0F0F0F0F0F0 },
		};

		uint64_t x, y;

		//
		x = (in[0] & mask[2][0]) | ((in[4] & mask[2][0]) << 4);
		y = ((in[0] & mask[2][1]) >> 4) | (in[4] & mask[2][1]);

		in[0] = x;
		in[4] = y;

		x = (in[1] & mask[2][0]) | ((in[5] & mask[2][0]) << 4);
		y = ((in[1] & mask[2][1]) >> 4) | (in[5] & mask[2][1]);

		in[1] = x;
		in[5] = y;

		x = (in[2] & mask[2][0]) | ((in[6] & mask[2][0]) << 4);
		y = ((in[2] & mask[2][1]) >> 4) | (in[6] & mask[2][1]);

		in[2] = x;
		in[6] = y;

		x = (in[3] & mask[2][0]) | ((in[7] & mask[2][0]) << 4);
		y = ((in[3] & mask[2][1]) >> 4) | (in[7] & mask[2][1]);

		in[3] = x;
		in[7] = y;

		//
		x = (in[0] & mask[1][0]) | ((in[2] & mask[1][0]) << 2);
		y = ((in[0] & mask[1][1]) >> 2) | (in[2] & mask[1][1]);

		in[0] = x;
		in[2] = y;

		x = (in[1] & mask[1][0]) | ((in[3] & mask[1][0]) << 2);
		y = ((in[1] & mask[1][1]) >> 2) | (in[3] & mask[1][1]);

		in[1] = x;
		in[3] = y;

		x = (in[4] & mask[1][0]) | ((in[6] & mask[1][0]) << 2);
		y = ((in[4] & mask[1][1]) >> 2) | (in[6] & mask[1][1]);

		in[4] = x;
		in[6] = y;

		x = (in[5] & mask[1][0]) | ((in[7] & mask[1][0]) << 2);
		y = ((in[5] & mask[1][1]) >> 2) | (in[7] & mask[1][1]);

		in[5] = x;
		in[7] = y;

		//
		x = (in[0] & mask[0][0]) | ((in[1] & mask[0][0]) << 1);
		y = ((in[0] & mask[0][1]) >> 1) | (in[1] & mask[0][1]);

		in[0] = x;
		in[1] = y;

		x = (in[2] & mask[0][0]) | ((in[3] & mask[0][0]) << 1);
		y = ((in[2] & mask[0][1]) >> 1) | (in[3] & mask[0][1]);

		in[2] = x;
		in[3] = y;

		x = (in[4] & mask[0][0]) | ((in[5] & mask[0][0]) << 1);
		y = ((in[4] & mask[0][1]) >> 1) | (in[5] & mask[0][1]);

		in[4] = x;
		in[5] = y;

		x = (in[6] & mask[0][0]) | ((in[7] & mask[0][0]) << 1);
		y = ((in[6] & mask[0][1]) >> 1) | (in[7] & mask[0][1]);

		in[6] = x;
		in[7] = y;
	}

	/////// benes.c

	static void func(uint64_t *bs, uint64_t *cond_ptr, int low) 
	{
		int i, j, x, y;
		int high = 5 - low;
		uint64_t diff;

		for (j = 0; j < (1 << low); j++) 
		{
			x = (0 << low) + j;
			y = (1 << low) + j;

			for (i = 0; i < (1 << high); i++) 
			{
				diff = bs[x] ^ bs[y];
				diff &= (*cond_ptr++);
				bs[x] ^= diff;
				bs[y] ^= diff;

				x += (1 << (low + 1));
				y += (1 << (low + 1));
			}
		}
	}

	static void benes_compact(uint64_t *bs, uint64_t *cond, int rev) 
	{
		uint64_t *cond_ptr;
		int inc, low;

		if (rev == 0) 
		{
			inc = 32;
			cond_ptr = cond;
		}
		else 
		{
			inc = -32;
			cond_ptr = &cond[704];
		}

		for (low = 0; low <= 5; low++) 
		{
			func(bs, cond_ptr, low);
			cond_ptr += inc;
		}

		transpose_64x64_compact(bs, bs);

		for (low = 0; low <= 5; low++) 
		{
			func(bs, cond_ptr, low);
			cond_ptr += inc;
		}
		for (low = 4; low >= 0; low--) 
		{
			func(bs, cond_ptr, low);
			cond_ptr += inc;
		}

		transpose_64x64_compact(bs, bs);

		for (low = 5; low >= 0; low--) 
		{
			func(bs, cond_ptr, low);
			cond_ptr += inc;
		}
	}

	/////// fft.c

	static void radix_conversions(uint64_t *in)
	{
		int i, j, k;

		for (j = 0; j <= 4; j++)
		{
			for (i = 0; i < GFBITS; i++)
				for (k = 4; k >= j; k--)
				{
					in[i] ^= (in[i] & RadixMask[k][0]) >> (1 << k);
					in[i] ^= (in[i] & RadixMask[k][1]) >> (1 << k);
				}

			vec_mul(in, in, RadixScalar[j].data()); // scaling
		}
	}

	static void butterflies(int64_t out[][GFBITS], uint64_t *in)
	{
		int i, j, k, s, b;

		uint64_t tmp[GFBITS];
		uint64_t consts_ptr = 0;

		// broadcast

		for (j = 0; j < 64; j++)
			for (i = 0; i < GFBITS; i++)
			{
				out[j][i] = (in[i] >> ButterflyReverse[j]) & 1;
				out[j][i] = -out[j][i];
			}

		// butterflies

		for (i = 0; i <= 5; i++)
		{
			s = 1 << i;

			for (j = 0; j < 64; j += 2 * s)
			{
				for (k = j; k < j + s; k++)
				{
					vec_mul(tmp, (uint64_t*)out[k + s], ButterflyConsts[consts_ptr + (k - j)].data());

					for (b = 0; b < GFBITS; b++)
						out[k][b] ^= tmp[b];
					for (b = 0; b < GFBITS; b++)
						out[k + s][b] ^= out[k][b];
				}
			}

			consts_ptr += (1 << i);
		}
	}

	static void fft(int64_t out[][GFBITS], uint64_t *in)
	{
		radix_conversions(in);
		butterflies(out, in);
	}

	/////// fft_tr.c

#define vec_add(z, x, y)           \
	for (b = 0; b < GFBITS; b++) { \
		z[b] = x[b] ^ y[b];        \
	}

	static void radix_conversions_tr(uint64_t in[][GFBITS])
	{
		int i, j, k;

		for (j = 5; j >= 0; j--) 
		{
			if (j < 5) {
				vec_mul(in[0], in[0], RadixTrScalar[j][0].data()); // scaling
				vec_mul(in[1], in[1], RadixTrScalar[j][1].data()); // scaling
			}

			for (i = 0; i < GFBITS; i++)
				for (k = j; k <= 4; k++) 
				{
					in[0][i] ^= (in[0][i] & RadixTrMask[k][0]) << (1 << k);
					in[0][i] ^= (in[0][i] & RadixTrMask[k][1]) << (1 << k);

					in[1][i] ^= (in[1][i] & RadixTrMask[k][0]) << (1 << k);
					in[1][i] ^= (in[1][i] & RadixTrMask[k][1]) << (1 << k);
				}

			for (i = 0; i < GFBITS; i++) 
			{
				in[1][i] ^= (in[0][i] & RadixTrMask[5][0]) >> 32;
				in[1][i] ^= (in[1][i] & RadixTrMask[5][1]) << 32;
			}
		}
	}

	static void butterflies_tr(uint64_t out[][GFBITS], uint64_t in[][GFBITS]) 
	{
		int i, j, k, s, b;
		int64_t tmp[GFBITS];
		uint64_t pre[6][GFBITS];
		uint64_t buf[64];
		uint64_t consts_ptr = 63;
		const uint16_t beta[6] = { 8, 1300, 3408, 1354, 2341, 1154 };

		// butterflies

		for (i = 5; i >= 0; i--) 
		{
			s = 1 << i;
			consts_ptr -= s;

			for (j = 0; j < 64; j += 2 * s)
				for (k = j; k < j + s; k++) 
				{
					vec_add(in[k], in[k], in[k + s]);
					vec_mul((uint64_t*)tmp, in[k], ButterflyConsts[consts_ptr + (k - j)].data());
					vec_add(in[k + s], in[k + s], tmp);
				}
		}

		// transpose

		for (i = 0; i < GFBITS; i++) 
		{
			for (j = 0; j < 64; j++)
				buf[ButterflyReverse[j]] = in[j][i];

			transpose_64x64_compact(buf, buf);

			for (j = 0; j < 64; j++)
				in[j][i] = buf[j];
		}

		// boradcast

		vec_copy(pre[0], in[32]);
		vec_add(in[33], in[33], in[32]);
		vec_copy(pre[1], in[33]);
		vec_add(in[35], in[35], in[33]);
		vec_add(pre[0], pre[0], in[35]);
		vec_add(in[34], in[34], in[35]);
		vec_copy(pre[2], in[34]);
		vec_add(in[38], in[38], in[34]);
		vec_add(pre[0], pre[0], in[38]);
		vec_add(in[39], in[39], in[38]);
		vec_add(pre[1], pre[1], in[39]);
		vec_add(in[37], in[37], in[39]);
		vec_add(pre[0], pre[0], in[37]);
		vec_add(in[36], in[36], in[37]);
		vec_copy(pre[3], in[36]);
		vec_add(in[44], in[44], in[36]);
		vec_add(pre[0], pre[0], in[44]);
		vec_add(in[45], in[45], in[44]);
		vec_add(pre[1], pre[1], in[45]);
		vec_add(in[47], in[47], in[45]);
		vec_add(pre[0], pre[0], in[47]);
		vec_add(in[46], in[46], in[47]);
		vec_add(pre[2], pre[2], in[46]);
		vec_add(in[42], in[42], in[46]);
		vec_add(pre[0], pre[0], in[42]);
		vec_add(in[43], in[43], in[42]);
		vec_add(pre[1], pre[1], in[43]);
		vec_add(in[41], in[41], in[43]);
		vec_add(pre[0], pre[0], in[41]);
		vec_add(in[40], in[40], in[41]);
		vec_copy(pre[4], in[40]);
		vec_add(in[56], in[56], in[40]);
		vec_add(pre[0], pre[0], in[56]);
		vec_add(in[57], in[57], in[56]);
		vec_add(pre[1], pre[1], in[57]);
		vec_add(in[59], in[59], in[57]);
		vec_add(pre[0], pre[0], in[59]);
		vec_add(in[58], in[58], in[59]);
		vec_add(pre[2], pre[2], in[58]);
		vec_add(in[62], in[62], in[58]);
		vec_add(pre[0], pre[0], in[62]);
		vec_add(in[63], in[63], in[62]);
		vec_add(pre[1], pre[1], in[63]);
		vec_add(in[61], in[61], in[63]);
		vec_add(pre[0], pre[0], in[61]);
		vec_add(in[60], in[60], in[61]);
		vec_add(pre[3], pre[3], in[60]);
		vec_add(in[52], in[52], in[60]);
		vec_add(pre[0], pre[0], in[52]);
		vec_add(in[53], in[53], in[52]);
		vec_add(pre[1], pre[1], in[53]);
		vec_add(in[55], in[55], in[53]);
		vec_add(pre[0], pre[0], in[55]);
		vec_add(in[54], in[54], in[55]);
		vec_add(pre[2], pre[2], in[54]);
		vec_add(in[50], in[50], in[54]);
		vec_add(pre[0], pre[0], in[50]);
		vec_add(in[51], in[51], in[50]);
		vec_add(pre[1], pre[1], in[51]);
		vec_add(in[49], in[49], in[51]);
		vec_add(pre[0], pre[0], in[49]);
		vec_add(in[48], in[48], in[49]);
		vec_copy(pre[5], in[48]);
		vec_add(in[16], in[16], in[48]);
		vec_add(pre[0], pre[0], in[16]);
		vec_add(in[17], in[17], in[16]);
		vec_add(pre[1], pre[1], in[17]);
		vec_add(in[19], in[19], in[17]);
		vec_add(pre[0], pre[0], in[19]);
		vec_add(in[18], in[18], in[19]);
		vec_add(pre[2], pre[2], in[18]);
		vec_add(in[22], in[22], in[18]);
		vec_add(pre[0], pre[0], in[22]);
		vec_add(in[23], in[23], in[22]);
		vec_add(pre[1], pre[1], in[23]);
		vec_add(in[21], in[21], in[23]);
		vec_add(pre[0], pre[0], in[21]);
		vec_add(in[20], in[20], in[21]);
		vec_add(pre[3], pre[3], in[20]);
		vec_add(in[28], in[28], in[20]);
		vec_add(pre[0], pre[0], in[28]);
		vec_add(in[29], in[29], in[28]);
		vec_add(pre[1], pre[1], in[29]);
		vec_add(in[31], in[31], in[29]);
		vec_add(pre[0], pre[0], in[31]);
		vec_add(in[30], in[30], in[31]);
		vec_add(pre[2], pre[2], in[30]);
		vec_add(in[26], in[26], in[30]);
		vec_add(pre[0], pre[0], in[26]);
		vec_add(in[27], in[27], in[26]);
		vec_add(pre[1], pre[1], in[27]);
		vec_add(in[25], in[25], in[27]);
		vec_add(pre[0], pre[0], in[25]);
		vec_add(in[24], in[24], in[25]);
		vec_add(pre[4], pre[4], in[24]);
		vec_add(in[8], in[8], in[24]);
		vec_add(pre[0], pre[0], in[8]);
		vec_add(in[9], in[9], in[8]);
		vec_add(pre[1], pre[1], in[9]);
		vec_add(in[11], in[11], in[9]);
		vec_add(pre[0], pre[0], in[11]);
		vec_add(in[10], in[10], in[11]);
		vec_add(pre[2], pre[2], in[10]);
		vec_add(in[14], in[14], in[10]);
		vec_add(pre[0], pre[0], in[14]);
		vec_add(in[15], in[15], in[14]);
		vec_add(pre[1], pre[1], in[15]);
		vec_add(in[13], in[13], in[15]);
		vec_add(pre[0], pre[0], in[13]);
		vec_add(in[12], in[12], in[13]);
		vec_add(pre[3], pre[3], in[12]);
		vec_add(in[4], in[4], in[12]);
		vec_add(pre[0], pre[0], in[4]);
		vec_add(in[5], in[5], in[4]);
		vec_add(pre[1], pre[1], in[5]);
		vec_add(in[7], in[7], in[5]);
		vec_add(pre[0], pre[0], in[7]);
		vec_add(in[6], in[6], in[7]);
		vec_add(pre[2], pre[2], in[6]);
		vec_add(in[2], in[2], in[6]);
		vec_add(pre[0], pre[0], in[2]);
		vec_add(in[3], in[3], in[2]);
		vec_add(pre[1], pre[1], in[3]);
		vec_add(in[1], in[1], in[3]);
		vec_add(pre[0], pre[0], in[1]);
		vec_add(out[0], in[0], in[1]);

		for (j = 0; j < GFBITS; j++) 
		{
			tmp[j] = (beta[0] >> j) & 1;
			tmp[j] = -tmp[j];
		}

		vec_mul(out[1], pre[0], (uint64_t*)tmp);

		for (i = 1; i < 6; i++)
		{
			for (j = 0; j < GFBITS; j++)
			{
				tmp[j] = (beta[i] >> j) & 1;
				tmp[j] = -tmp[j];
			}

			vec_mul((uint64_t*)tmp, pre[i], (uint64_t*)tmp);
			vec_add(out[1], out[1], tmp);
		}
	}

	static void fft_tr(uint64_t out[][GFBITS], uint64_t in[][GFBITS]) 
	{
		butterflies_tr(out, in);
		radix_conversions_tr(out);
	}

	/////// sk_gen.c

	static int irr_gen(gf *out, gf *f) 
	{
		int i, j, k, c;

		gf mat[SYS_T + 1][SYS_T];
		gf mask, inv, t;

		// fill matrix

		mat[0][0] = 1;
		for (i = 1; i < SYS_T; i++)
			mat[0][i] = 0;

		for (i = 0; i < SYS_T; i++)
			mat[1][i] = f[i];

		for (j = 2; j <= SYS_T; j++)
			GF_mul(mat[j], mat[j - 1], f);

		// gaussian

		for (j = 0; j < SYS_T; j++) 
		{
			for (k = j + 1; k < SYS_T; k++)
			{
				mask = gf_diff(mat[j][j], mat[j][k]);

				for (c = 0; c < SYS_T + 1; c++)
					mat[c][j] ^= mat[c][k] & mask;
			}

			if (mat[j][j] == 0)
			{ // return if not invertible
				return -1;
			}

			// compute inverse

			inv = gf_inv(mat[j][j]);

			for (c = 0; c < SYS_T + 1; c++)
				mat[c][j] = gf_mul(mat[c][j], inv);

			//

			for (k = 0; k < SYS_T; k++)
			{
				t = mat[j][k];

				if (k != j) {
					for (c = 0; c < SYS_T + 1; c++)
						mat[c][k] ^= gf_mul(mat[c][j], t);
				}
			}
		}

		//

		for (i = 0; i < SYS_T; i++)
			out[i] = mat[SYS_T][i];

		out[SYS_T] = 1;

		return 0;
	}

	static void GetRand(Prng::IPrng* Rng, byte* f, size_t len)
	{
		std::vector<byte> r(len);
		Rng->GetBytes(r);
		memcpy(f, r.data(), len);
	}

	static void sk_gen(unsigned char *sk, Prng::IPrng* Rng)
	{
		uint64_t cond[COND_BYTES / 8];
		uint64_t sk_int[GFBITS];

		int i, j;

		gf irr[SYS_T + 1]; //63
		gf f[SYS_T]; //62

		while (1)
		{
			//OQS_RAND_n(r, (uint8_t *)f, sizeof(f));
			GetRand(Rng, (uint8_t*)f, sizeof(f));

			for (i = 0; i < SYS_T; i++)
				f[i] &= (1 << GFBITS) - 1;

			if (irr_gen(irr, f) == 0)
				break;
		}

		for (i = 0; i < GFBITS; i++)
		{
			sk_int[i] = 0;

			for (j = SYS_T; j >= 0; j--)
			{
				sk_int[i] <<= 1;
				sk_int[i] |= (irr[j] >> i) & 1;
			}

			store8(sk + i * 8, sk_int[i]);
		}

		//

		//OQS_RAND_n(r, (uint8_t *)cond, sizeof(cond));
		GetRand(Rng, (uint8_t*)cond, sizeof(cond));

		for (i = 0; i < COND_BYTES / 8; i++)
			store8(sk + IRR_BYTES + i * 8, cond[i]);
	}

	/////// pk_gen.c

	static int pk_gen(unsigned char *pk, const unsigned char *sk) 
	{
		unsigned char *pk_ptr = pk;

		int i, j, k;
		int row, c, tail;

		uint64_t mat[GFBITS * SYS_T][64];
		int64_t mask;
		uint64_t u;

		uint64_t sk_int[GFBITS];

		int64_t eval[64][GFBITS];
		uint64_t inv[64][GFBITS];
		uint64_t tmp[GFBITS];

		uint64_t cond[COND_BYTES / 8];

		// compute the inverses

		for (i = 0; i < GFBITS; i++)
			sk_int[i] = load8(sk + i * 8);

		fft(eval, sk_int);

		vec_copy(inv[0], (uint64_t*)eval[0]);

		for (i = 1; i < 64; i++)
			vec_mul(inv[i], inv[i - 1], (uint64_t*)eval[i]);

		vec_inv(tmp, inv[63]);

		for (i = 62; i >= 0; i--) 
		{
			vec_mul(inv[i + 1], tmp, inv[i]);
			vec_mul(tmp, tmp, (uint64_t*)eval[i + 1]);
		}

		vec_copy(inv[0], tmp);

		// fill matrix

		for (j = 0; j < 64; j++)
			for (k = 0; k < GFBITS; k++)
				mat[k][j] = inv[j][k];

		for (i = 1; i < SYS_T; i++)
			for (j = 0; j < 64; j++)
			{
				vec_mul(inv[j], inv[j], GfPoints[j].data());

				for (k = 0; k < GFBITS; k++)
					mat[i * GFBITS + k][j] = inv[j][k];
			}

		// permute

		for (i = 0; i < COND_BYTES / 8; i++)
			cond[i] = load8(sk + IRR_BYTES + i * 8);

		for (i = 0; i < GFBITS * SYS_T; i++)
			benes_compact(mat[i], cond, 0);

		// gaussian elimination

		for (i = 0; i < (GFBITS * SYS_T + 63) / 64; i++)
			for (j = 0; j < 64; j++) 
			{
				row = i * 64 + j;

				if (row >= GFBITS * SYS_T)
					break;

				for (k = row + 1; k < GFBITS * SYS_T; k++) 
				{
					mask = mat[row][i] ^ mat[k][i];
					mask >>= j;
					mask &= 1;
					mask = -mask;

					for (c = 0; c < 64; c++)
						mat[row][c] ^= mat[k][c] & (uint64_t)mask;
				}

				if (((mat[row][i] >> j) & 1) == 0)
				{ // return if not invertible
					return -1;
				}

				for (k = 0; k < GFBITS * SYS_T; k++) 
				{
					if (k != row) {
						mask = mat[k][i] >> j;
						mask &= 1;
						mask = -mask;

						for (c = 0; c < 64; c++)
							mat[k][c] ^= mat[row][c] & (uint64_t)mask;
					}
				}
			}

		// store pk

		tail = ((GFBITS * SYS_T) & 63) >> 3;

		for (i = 0; i < GFBITS * SYS_T; i++) 
		{
			u = mat[i][(GFBITS * SYS_T + 63) / 64 - 1];

			for (k = tail; k < 8; k++)
				pk_ptr[k - tail] = (u >> (8 * k)) & 0xFF;

			pk_ptr += 8 - tail;

			for (j = (GFBITS * SYS_T + 63) / 64; j < 64; j++) 
			{
				store8(pk_ptr, mat[i][j]);

				pk_ptr += 8;
			}
		}

		return 0;
	}

	/////// util.c

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

	/////// decrypt.c

	static void scaling(uint64_t out[][GFBITS], uint64_t inv[][GFBITS], const unsigned char *sk, uint64_t *recv) 
	{
		int i, j;
		uint64_t sk_int[GFBITS];

		int64_t eval[64][GFBITS];
		uint64_t tmp[GFBITS];

		// computing inverses

		for (i = 0; i < GFBITS; i++)
			sk_int[i] = load8(sk + i * 8);

		fft(eval, sk_int);

		for (i = 0; i < 64; i++)
			vec_sq((uint64_t*)eval[i], (uint64_t*)eval[i]);

		vec_copy(inv[0], (uint64_t*)eval[0]);

		for (i = 1; i < 64; i++)
			vec_mul(inv[i], inv[i - 1], (uint64_t*)eval[i]);

		vec_inv(tmp, inv[63]);

		for (i = 62; i >= 0; i--)
		{
			vec_mul(inv[i + 1], tmp, inv[i]);
			vec_mul(tmp, tmp, (uint64_t*)eval[i + 1]);
		}

		vec_copy(inv[0], tmp);

		for (i = 0; i < 64; i++)
			for (j = 0; j < GFBITS; j++)
				out[i][j] = inv[i][j] & recv[i];
	}

	static void scaling_inv(uint64_t out[][GFBITS], uint64_t inv[][GFBITS], uint64_t *recv) 
	{
		int i, j;

		for (i = 0; i < 64; i++)
			for (j = 0; j < GFBITS; j++)
				out[i][j] = inv[i][j] & recv[i];
	}

	static void preprocess(uint64_t *recv, const unsigned char *s) 
	{
		int i;

		for (i = 0; i < 64; i++)
			recv[i] = 0;

		for (i = 0; i < SYND_BYTES / 8; i++)
			recv[i] = load8(s + i * 8);

		for (i = SYND_BYTES % 8 - 1; i >= 0; i--) 
		{
			recv[SYND_BYTES / 8] <<= 8;
			recv[SYND_BYTES / 8] |= s[SYND_BYTES / 8 * 8 + i];
		}
	}

	static void acc(uint64_t *c, uint64_t v) 
	{
		int i;

		uint64_t carry = v;
		uint64_t t;

		for (i = 0; i < 8; i++) 
		{
			t = c[i] ^ carry;
			carry = c[i] & carry;

			c[i] = t;
		}
	}

	static int weight(uint64_t *v)
	{
		int i;
		int w;

		union 
		{
			uint64_t data_64[8];
			uint8_t data_8[64];
		} counter;

		for (i = 0; i < 8; i++)
			counter.data_64[i] = 0;

		for (i = 0; i < 64; i++)
			acc(counter.data_64, v[i]);

		transpose_8x64(counter.data_64);

		w = 0;
		for (i = 0; i < 64; i++)
			w += counter.data_8[i];

		return w;
	}

	static void syndrome_adjust(uint64_t in[][GFBITS])
	{
		int i;

		for (i = 0; i < GFBITS; i++)
		{
			in[1][i] <<= (128 - SYS_T * 2);
			in[1][i] >>= (128 - SYS_T * 2);
		}
	}

	static int decrypt(unsigned char *e, const unsigned char *sk, const unsigned char *s) 
	{
		int i, j;

		uint64_t t;

		uint64_t diff;

		uint64_t inv[64][GFBITS];
		uint64_t scaled[64][GFBITS];
		int64_t eval[64][GFBITS];

		uint64_t error[64];

		uint64_t s_priv[2][GFBITS];
		uint64_t s_priv_cmp[2][GFBITS];
		uint64_t locator[GFBITS];

		uint64_t recv[64];
		uint64_t cond[COND_BYTES / 8];

		//

		for (i = 0; i < COND_BYTES / 8; i++)
			cond[i] = load8(sk + IRR_BYTES + i * 8);

		preprocess(recv, s);
		benes_compact(recv, cond, 1);
		scaling(scaled, inv, sk, recv); // scaling
		fft_tr(s_priv, scaled);         // transposed FFT
		syndrome_adjust(s_priv);
		bm(locator, s_priv); // Berlekamp Massey
		fft(eval, locator);  // FFT

		for (i = 0; i < 64; i++) 
		{
			error[i] = vec_or((uint64_t*)eval[i]);
			error[i] = ~error[i];
		}

		{
			// reencrypt

			scaling_inv(scaled, inv, error);
			fft_tr(s_priv_cmp, scaled);
			syndrome_adjust(s_priv_cmp);

			diff = 0;
			for (i = 0; i < 2; i++)
				for (j = 0; j < GFBITS; j++)
					diff |= s_priv[i][j] ^ s_priv_cmp[i][j];

			diff |= diff >> 32;
			diff |= diff >> 16;
			diff |= diff >> 8;
			t = diff & 0xFF;
		}

		benes_compact(error, cond, 0);

		for (i = 0; i < 64; i++)
			store8(e + i * 8, error[i]);

		t |= weight(error) ^ SYS_T;
		t -= 1;
		t >>= 63;

		return (t - 1);
	}

	/////// encrypt.c

	static void gen_e(unsigned char *e, Prng::IPrng *r)
	{
		int i, j, eq;

		uint16_t ind[SYS_T];
		uint64_t e_int[64];
		uint64_t one = 1;
		int64_t mask;
		uint64_t val[SYS_T];

		while (1) 
		{
			//OQS_RAND_n(r, (uint8_t *)ind, sizeof(ind));
			GetRand(r, (uint8_t*)ind, sizeof(ind));

			for (i = 0; i < SYS_T; i++)
				ind[i] &= (1 << GFBITS) - 1;

			eq = 0;
			for (i = 1; i < SYS_T; i++)
			{
				for (j = 0; j < i; j++)
				{
					if (ind[i] == ind[j])
						eq = 1;
				}
			}

			if (eq == 0)
				break;
		}

		for (j = 0; j < SYS_T; j++)
			val[j] = one << (ind[j] & 63);

		for (i = 0; i < 64; i++) 
		{
			e_int[i] = 0;

			for (j = 0; j < SYS_T; j++) 
			{
				mask = i ^ (ind[j] >> 6);
				mask -= 1;
				mask >>= 63;
				mask = -mask;

				e_int[i] |= val[j] & (uint64_t)mask;
			}
		}

		for (i = 0; i < 64; i++)
			store8(e + i * 8, e_int[i]);
	}

#define C ((PK_NCOLS + 63) / 64)

	static void syndrome(unsigned char *s, const unsigned char *pk, const unsigned char *e) 
	{
		int i, j, t;

		const unsigned char *e_ptr = e + SYND_BYTES;

		uint64_t e_int[C];
		uint64_t row_int[C];
		uint64_t tmp[8];
		unsigned char b;

		memcpy(s, e, SYND_BYTES);

		e_int[C - 1] = 0;
		memcpy(e_int, e_ptr, PK_NCOLS / 8);

		for (i = 0; i < PK_NROWS; i += 8) 
		{
			for (t = 0; t < 8; t++)
			{
				row_int[C - 1] = 0;
				memcpy(row_int, &pk[(i + t) * (PK_NCOLS / 8)], PK_NCOLS / 8);

				tmp[t] = 0;
				for (j = 0; j < C; j++)
					tmp[t] ^= e_int[j] & row_int[j];
			}

			b = 0;

			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 32);
			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 16);
			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 8);
			for (t = 7; t >= 0; t--)
				tmp[t] ^= (tmp[t] >> 4);
			for (t = 7; t >= 0; t--)
			{
				b <<= 1;
				b |= (0x6996 >> (tmp[t] & 0xF)) & 1;
			}

			s[i / 8] ^= b;
		}
	}

	static void encrypt(unsigned char *s, unsigned char *e, const unsigned char *pk, Prng::IPrng *r)
	{
		gen_e(e, r);
		syndrome(s, pk, e);
	}

	/////// operations.c

public:
	static int oqs_kex_mcbits_encrypt(std::vector<byte> &c, size_t clen, std::vector<byte> &m, ulong mlen, const std::vector<byte> &pk, Prng::IPrng *r)
	{
		std::vector<byte> e(1 << (GFBITS - 3));
		std::vector<byte> key(64);
		std::vector<byte> nonce(8);

		//

#define ct (c + SYND_BYTES)
#define tag (ct + mlen)

		encrypt((byte*)c.data(), (byte*)e.data(), (byte*)pk.data(), r);

		//crypto_hash_keccakc1024(key, e, sizeof(e)); TODO is this ok to replace with the below?
		//OQS_SHA3_sha3512(key, e, sizeof(e));

		//crypto_stream_salsa20_xor(ct, m, mlen, nonce, key);
		//crypto_onetimeauth_poly1305(tag, ct, mlen, key + 32);

		clen = SYND_BYTES + mlen + 16;

#undef ct
#undef tag

		return 0;
	}

	static int oqs_kex_mcbits_decrypt(std::vector<byte> &m, size_t mlen, std::vector<byte> &c, ulong clen, const std::vector<byte> &sk)
	{
		int ret;
		int ret_verify;
		int ret_decrypt;

		std::vector<byte> key(64);
		std::vector<byte> nonce(8);
		std::vector<byte> e(1 << (GFBITS - 3));

		//

		if (clen < SYND_BYTES + 16)
			return -1;
		else
			mlen = clen - SYND_BYTES - 16;

#define ct (c + SYND_BYTES)
#define tag (ct + *mlen)

		ret_decrypt = decrypt(e.data(), sk.data(), c.data());

		//crypto_hash_keccakc1024(key, e, sizeof(e)); TODO is this ok to replace with the below?
		//OQS_SHA3_sha3512(key, e, sizeof(e));

		//ret_verify = crypto_onetimeauth_poly1305_verify(tag, ct, *mlen, key + 32);
		//crypto_stream_salsa20_xor(m, ct, *mlen, nonce, key);
		m = c;
		ret = /*ret_verify |*/ ret_decrypt;

#undef ct
#undef tag

		return ret;
	}

	static int oqs_kex_mcbits_gen_keypair(std::vector<byte> &pk, std::vector<byte> &sk, Prng::IPrng *r)
	{
		pk.resize(CRYPTO_PUBLICKEYBYTES);
		sk.resize(CRYPTO_SECRETKEYBYTES);

		while (1)
		{
			sk_gen(sk.data(), r);

			if (pk_gen(pk.data(), sk.data()) == 0)
				break;
		}

		return 0;
	}
};

NAMESPACE_MCELIECEEND
#endif