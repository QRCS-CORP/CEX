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

#ifndef CEX_RIJNDAEL_H
#define CEX_RIJNDAEL_H

#include "CexDomain.h"
#include "IntegerTools.h"

NAMESPACE_RIJNDAELBASE

using Tools::IntegerTools;

//~~~Rijndael-based ciphers internal constants~~~//

/// <summary>
/// The Rijndael-128 output size in bytes
/// </summary>
static const size_t RJD128_BLOCK_SIZE = 16;

/// <summary>
/// The Rijndael-256 output size in bytes
/// </summary>
static const size_t RJD256_BLOCK_SIZE = 32;

/// <summary>
/// The Rijndael-512 output size in bytes
/// </summary>
static const size_t RJD512_BLOCK_SIZE = 64;

/// 
/// internal
/// 

static const std::array<uint, 30> Rcon =
{
	0x00000000UL, 0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL, 0x20000000UL, 0x40000000UL,
	0x80000000UL, 0x1B000000UL, 0x36000000UL, 0x6C000000UL, 0xD8000000UL, 0xAB000000UL, 0x4D000000UL, 0x9A000000UL,
	0x2F000000UL, 0x5E000000UL, 0xBC000000UL, 0x63000000UL, 0xC6000000UL, 0x97000000UL, 0x35000000UL, 0x6A000000UL,
	0xD4000000UL, 0xB3000000UL, 0x7D000000UL, 0xFA000000UL, 0xEF000000UL, 0xC5000000UL
};

//~~~Rijndael S-Box Tables~~~//

static const std::vector<byte> ISBox =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const std::vector<byte> SBox =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Rijndael 128/256-bit block functions

static byte Gf256Reduce(uint X)
{
	uint y;

	y = X >> 8;

	return static_cast<byte>((X ^ y ^ (y << 1) ^ (y << 3) ^ (y << 4)) & 0xFF);
}

template<typename ArrayU8, typename ArrayU32>
static void KeyAddition(ArrayU8 &State, const ArrayU32 &Rkeys, size_t RkOffset)
{
	size_t i;
	uint k;

	for (i = 0; i < State.size(); i += sizeof(uint))
	{
		k = Rkeys[RkOffset + (i / sizeof(uint))];

		State[i] ^= static_cast<byte>(k >> 24);
		State[i + 1] ^= static_cast<byte>(k >> 16) & 0xFF;
		State[i + 2] ^= static_cast<byte>(k >> 8) & 0xFF;
		State[i + 3] ^= static_cast<byte>(k) & 0xFF;
	}
}

template<typename ArrayU8>
static void InvMixColumns(ArrayU8 &State)
{
	size_t i;
	uint s0;
	uint s1;
	uint s2;
	uint s3;
	uint t0;
	uint t1;
	uint t2;
	uint t3;

	for (i = 0; i < State.size(); i += sizeof(uint))
	{
		s0 = State[i + 0];
		s1 = State[i + 1];
		s2 = State[i + 2];
		s3 = State[i + 3];

		t0 = (s0 << 1) ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 1) ^ (s1 << 3)
			^ s2 ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 3);

		t1 = s0 ^ (s0 << 3) ^ (s1 << 1) ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 1) ^ (s2 << 3) ^ s3 ^ (s3 << 2) ^ (s3 << 3);

		t2 = s0 ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 3)
			^ (s2 << 1) ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 1) ^ (s3 << 3);

		t3 = s0 ^ (s0 << 1) ^ (s0 << 3) ^ s1 ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 3) ^ (s3 << 1) ^ (s3 << 2) ^ (s3 << 3);

		State[i + 0] = Gf256Reduce(t0);
		State[i + 1] = Gf256Reduce(t1);
		State[i + 2] = Gf256Reduce(t2);
		State[i + 3] = Gf256Reduce(t3);
	}
}

template<typename ArrayU8>
static void InvShiftRows(ArrayU8 &State)
{
	byte tmp;

	tmp = State[13];
	State[13] = State[9];
	State[9] = State[5];
	State[5] = State[1];
	State[1] = tmp;

	tmp = State[2];
	State[2] = State[10];
	State[10] = tmp;
	tmp = State[6];
	State[6] = State[14];
	State[14] = tmp;

	tmp = State[3];
	State[3] = State[7];
	State[7] = State[11];
	State[11] = State[15];
	State[15] = tmp;
}

template<typename ArrayU8>
static void InvSubBytes(ArrayU8 &State)
{
	size_t i;

	for (i = 0; i < State.size(); ++i)
	{
		State[i] = ISBox[State[i]];
	}
}

template<typename ArrayU8>
static void MixColumns(ArrayU8 &State)
{
	size_t i;
	uint s0;
	uint s1;
	uint s2;
	uint s3;
	uint t0;
	uint t1;
	uint t2;
	uint t3;

	for (i = 0; i < State.size(); i += sizeof(uint))
	{
		s0 = State[i + 0];
		s1 = State[i + 1];
		s2 = State[i + 2];
		s3 = State[i + 3];

		t0 = (s0 << 1) ^ s1 ^ (s1 << 1) ^ s2 ^ s3;
		t1 = s0 ^ (s1 << 1) ^ s2 ^ (s2 << 1) ^ s3;
		t2 = s0 ^ s1 ^ (s2 << 1) ^ s3 ^ (s3 << 1);
		t3 = s0 ^ (s0 << 1) ^ s1 ^ s2 ^ (s3 << 1);

		State[i + 0] = t0 ^ ((~(t0 >> 8) + 1) & 0x0000011BUL);
		State[i + 1] = t1 ^ ((~(t1 >> 8) + 1) & 0x0000011BUL);
		State[i + 2] = t2 ^ ((~(t2 >> 8) + 1) & 0x0000011BUL);
		State[i + 3] = t3 ^ ((~(t3 >> 8) + 1) & 0x0000011BUL);
	}
}

template<typename ArrayU8>
static void ShiftRows128(ArrayU8 &State)
{
	byte tmp;

	// row 0 - unchanged

	// row 1
	tmp = State[1];
	State[1] = State[5];
	State[5] = State[9];
	State[9] = State[13];
	State[13] = tmp;

	// row 2
	tmp = State[2];
	State[2] = State[10];
	State[10] = tmp;
	tmp = State[6];
	State[6] = State[14];
	State[14] = tmp;

	// row 3
	tmp = State[15];
	State[15] = State[11];
	State[11] = State[7];
	State[7] = State[3];
	State[3] = tmp;
}

template<typename ArrayU8>
static void ShiftRows256(ArrayU8 &State)
{
	byte tmp;

	tmp = State[1];
	State[1] = State[5];
	State[5] = State[9];
	State[9] = State[13];
	State[13] = State[17];
	State[17] = State[21];
	State[21] = State[25];
	State[25] = State[29];
	State[29] = tmp;

	tmp = State[2];
	State[2] = State[14];
	State[14] = State[26];
	State[26] = State[6];
	State[6] = State[18];
	State[18] = State[30];
	State[30] = State[10];
	State[10] = State[22];
	State[22] = tmp;

	tmp = State[3];
	State[3] = State[19];
	State[19] = tmp;
	tmp = State[7];
	State[7] = State[23];
	State[23] = tmp;
	tmp = State[11];
	State[11] = State[27];
	State[27] = tmp;
	tmp = State[15];
	State[15] = State[31];
	State[31] = tmp;
}

template<typename ArrayU8>
static void ShiftRows512(ArrayU8 &State)
{
	byte tmp;

	tmp = State[0];
	State[0] = State[4];
	State[4] = State[8];
	State[8] = State[12];
	State[12] = State[16];
	State[16] = State[20];
	State[20] = State[24];
	State[24] = State[28]; 
	State[28] = State[32];
	State[32] = State[36];
	State[36] = State[40];
	State[40] = State[44];
	State[44] = State[48];
	State[48] = State[52];
	State[52] = State[56];
	State[56] = State[60];
	State[60] = tmp;

	tmp = State[1];
	State[1] = State[9];
	State[9] = State[17];
	State[17] = State[25];
	State[25] = State[33];
	State[33] = State[41];
	State[41] = State[49];
	State[49] = State[57];
	State[57] = tmp;
	tmp = State[5];
	State[5] = State[13];
	State[13] = State[21];
	State[21] = State[29];
	State[29] = State[37];
	State[37] = State[45];
	State[45] = State[53];
	State[53] = State[61];
	State[61] = tmp;

	tmp = State[2];
	State[2] = State[18];
	State[18] = State[34];
	State[34] = State[50];
	State[50] = tmp;
	tmp = State[6];
	State[6] = State[22];
	State[22] = State[38];
	State[38] = State[54];
	State[54] = tmp;
	tmp = State[10];
	State[10] = State[26];
	State[26] = State[42];
	State[42] = State[58];
	State[58] = tmp;
	tmp = State[14];
	State[14] = State[30];
	State[30] = State[46];
	State[46] = State[62];
	State[62] = tmp;

	tmp = State[3];
	State[3] = State[35];
	State[35] = tmp;
	tmp = State[7];
	State[7] = State[39];
	State[39] = tmp;
	tmp = State[11];
	State[11] = State[43];
	State[43] = tmp;
	tmp = State[15];
	State[15] = State[47];
	State[47] = tmp;
	tmp = State[19];
	State[19] = State[51];
	State[51] = tmp;
	tmp = State[23];
	State[23] = State[55];
	State[55] = tmp;
	tmp = State[27];
	State[27] = State[59];
	State[59] = tmp;
	tmp = State[31];
	State[31] = State[63];
	State[63] = tmp;
}

template<typename ArrayU8>
static void Substitution(ArrayU8 &State)
{
	size_t i;

	for (i = 0; i < State.size(); ++i)
	{
		State[i] = SBox[State[i]];
	}
}

// TODO: Not working, fix or remove
template<typename ArrayU8>
static void Substitution256(ArrayU8 &State)
{
	// This S-box implementation is a straightforward translation of
	// the circuit described by Boyar and Peralta in "A new
	// combinational logic minimization technique with applications
	// to cryptology" (https://eprint.iacr.org/2009/191.pdf).
	// Note that variables x* (input) and s* (output) are numbered
	// in "reverse" order (x0 is the high bit, x7 is the low bit).

	uint x0; 
	uint x1; 
	uint x2; 
	uint x3; 
	uint x4; 
	uint x5; 
	uint x6; 
	uint x7;
	uint y1; 
	uint y2; 
	uint y3; 
	uint y4; 
	uint y5; 
	uint y6; 
	uint y7; 
	uint y8; 
	uint y9;
	uint y10; 
	uint y11; 
	uint y12; 
	uint y13; 
	uint y14; 
	uint y15; 
	uint y16; 
	uint y17; 
	uint y18; 
	uint y19;
	uint y20; 
	uint y21;
	uint z0; 
	uint z1; 
	uint z2; 
	uint z3; 
	uint z4; 
	uint z5;
	uint z6; 
	uint z7; 
	uint z8;
	uint z9;
	uint z10; 
	uint z11; 
	uint z12; 
	uint z13; 
	uint z14; 
	uint z15; 
	uint z16;
	uint z17;
	uint t0; 
	uint t1; 
	uint t2; 
	uint t3; 
	uint t4; 
	uint t5; 
	uint t6; 
	uint t7; 
	uint t8; 
	uint t9;
	uint t10; 
	uint t11; 
	uint t12; 
	uint t13; 
	uint t14; 
	uint t15;
	uint t16; 
	uint t17; 
	uint t18; 
	uint t19;
	uint t20; 
	uint t21;
	uint t22;
	uint t23; 
	uint t24;
	uint t25; 
	uint t26; 
	uint t27; 
	uint t28; 
	uint t29;
	uint t30; 
	uint t31; 
	uint t32;
	uint t33; 
	uint t34;
	uint t35; 
	uint t36;
	uint t37; 
	uint t38; 
	uint t39;
	uint t40; 
	uint t41; 
	uint t42; 
	uint t43;
	uint t44;
	uint t45; 
	uint t46; 
	uint t47; 
	uint t48; 
	uint t49;
	uint t50; 
	uint t51;
	uint t52; 
	uint t53;
	uint t54; 
	uint t55;
	uint t56;
	uint t57;
	uint t58;
	uint t59;
	uint t60;
	uint t61;
	uint t62; 
	uint t63;
	uint t64;
	uint t65; 
	uint t66;
	uint t67;
	uint s0; 
	uint s1;
	uint s2; 
	uint s3; 
	uint s4; 
	uint s5; 
	uint s6;
	uint s7;

	x7 = IntegerTools::BeBytesTo32(State, 0);
	x6 = IntegerTools::BeBytesTo32(State, 4);
	x5 = IntegerTools::BeBytesTo32(State, 8);
	x4 = IntegerTools::BeBytesTo32(State, 12);
	x3 = IntegerTools::BeBytesTo32(State, 16);
	x2 = IntegerTools::BeBytesTo32(State, 20);
	x1 = IntegerTools::BeBytesTo32(State, 24);
	x0 = IntegerTools::BeBytesTo32(State, 28);

	// top linear transformation.
	y14 = x3 ^ x5;
	y13 = x0 ^ x6;
	y9 = x0 ^ x3;
	y8 = x0 ^ x5;
	t0 = x1 ^ x2;
	y1 = t0 ^ x7;
	y4 = y1 ^ x3;
	y12 = y13 ^ y14;
	y2 = y1 ^ x0;
	y5 = y1 ^ x6;
	y3 = y5 ^ y8;
	t1 = x4 ^ y12;
	y15 = t1 ^ x5;
	y20 = t1 ^ x1;
	y6 = y15 ^ x7;
	y10 = y15 ^ t0;
	y11 = y20 ^ y9;
	y7 = x7 ^ y11;
	y17 = y10 ^ y11;
	y19 = y10 ^ y8;
	y16 = t0 ^ y11;
	y21 = y13 ^ y16;
	y18 = x0 ^ y16;
	// non-linear section
	t2 = y12 & y15;
	t3 = y3 & y6;
	t4 = t3 ^ t2;
	t5 = y4 & x7;
	t6 = t5 ^ t2;
	t7 = y13 & y16;
	t8 = y5 & y1;
	t9 = t8 ^ t7;
	t10 = y2 & y7;
	t11 = t10 ^ t7;
	t12 = y9 & y11;
	t13 = y14 & y17;
	t14 = t13 ^ t12;
	t15 = y8 & y10;
	t16 = t15 ^ t12;
	t17 = t4 ^ t14;
	t18 = t6 ^ t16;
	t19 = t9 ^ t14;
	t20 = t11 ^ t16;
	t21 = t17 ^ y20;
	t22 = t18 ^ y19;
	t23 = t19 ^ y21;
	t24 = t20 ^ y18;
	t25 = t21 ^ t22;
	t26 = t21 & t23;
	t27 = t24 ^ t26;
	t28 = t25 & t27;
	t29 = t28 ^ t22;
	t30 = t23 ^ t24;
	t31 = t22 ^ t26;
	t32 = t31 & t30;
	t33 = t32 ^ t24;
	t34 = t23 ^ t33;
	t35 = t27 ^ t33;
	t36 = t24 & t35;
	t37 = t36 ^ t34;
	t38 = t27 ^ t36;
	t39 = t29 & t38;
	t40 = t25 ^ t39;
	t41 = t40 ^ t37;
	t42 = t29 ^ t33;
	t43 = t29 ^ t40;
	t44 = t33 ^ t37;
	t45 = t42 ^ t41;
	z0 = t44 & y15;
	z1 = t37 & y6;
	z2 = t33 & x7;
	z3 = t43 & y16;
	z4 = t40 & y1;
	z5 = t29 & y7;
	z6 = t42 & y11;
	z7 = t45 & y17;
	z8 = t41 & y10;
	z9 = t44 & y12;
	z10 = t37 & y3;
	z11 = t33 & y4;
	z12 = t43 & y13;
	z13 = t40 & y5;
	z14 = t29 & y2;
	z15 = t42 & y9;
	z16 = t45 & y14;
	z17 = t41 & y8;
	// bottom linear transformation
	t46 = z15 ^ z16;
	t47 = z10 ^ z11;
	t48 = z5 ^ z13;
	t49 = z9 ^ z10;
	t50 = z2 ^ z12;
	t51 = z2 ^ z5;
	t52 = z7 ^ z8;
	t53 = z0 ^ z3;
	t54 = z6 ^ z7;
	t55 = z16 ^ z17;
	t56 = z12 ^ t48;
	t57 = t50 ^ t53;
	t58 = z4 ^ t46;
	t59 = z3 ^ t54;
	t60 = t46 ^ t57;
	t61 = z14 ^ t57;
	t62 = t52 ^ t58;
	t63 = t49 ^ t58;
	t64 = z4 ^ t59;
	t65 = t61 ^ t62;
	t66 = z1 ^ t63;
	s0 = t59 ^ t63;
	s6 = t56 ^ ~t62;
	s7 = t48 ^ ~t60;
	t67 = t64 ^ t65;
	s3 = t53 ^ t66;
	s4 = t51 ^ t66;
	s5 = t47 ^ t65;
	s1 = t64 ^ ~s3;
	s2 = t55 ^ ~t67;

	IntegerTools::Be32ToBytes(s7, State, 0);
	IntegerTools::Be32ToBytes(s6, State, 4);
	IntegerTools::Be32ToBytes(s5, State, 8);
	IntegerTools::Be32ToBytes(s4, State, 12);
	IntegerTools::Be32ToBytes(s3, State, 16);
	IntegerTools::Be32ToBytes(s2, State, 20);
	IntegerTools::Be32ToBytes(s1, State, 24);
	IntegerTools::Be32ToBytes(s0, State, 28);
}

template<typename ArrayU8>
static uint SubWord(uint X, const ArrayU8 &Sbox)
{
	return (static_cast<uint>(Sbox[X >> 24] << 24))
		| (static_cast<uint>(Sbox[(X >> 16) & 0xFF] << 16))
		| (static_cast<uint>(Sbox[(X >> 8) & 0xFF] << 8))
		| static_cast<uint>(Sbox[X & 0xFF]);
}


NAMESPACE_RIJNDAELBASEEND
#endif

