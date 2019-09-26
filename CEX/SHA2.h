// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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

#ifndef CEX_SHA2_H
#define CEX_SHA2_H

#include "CexDomain.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

#if defined(__AVX2__)
#	include "UInt256.h"
#	include "ULong256.h"
#endif
#if defined(__AVX512__)
#	include "UInt512.h"
#	include "ULong512.h"
#endif

NAMESPACE_DIGEST

using Utility::IntegerTools;
using Utility::MemoryTools;

#if defined(__AVX2__)
	using Numeric::UInt256;
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::UInt512;
	using Numeric::ULong512;
#endif

/// <summary>
/// Contains the SHA2-256 and 512bit permutation functions.
/// <para>The function names are in the format; Permute-rounds-bits-suffix, ex. PermuteR64P512C, 64 rounds, permutes 512 bits, using the compact form of the function. \n
/// The compact forms of the permutations have the suffix C, and are optimized for performance and low memory consumption 
/// (enabled in the hash function by adding the CEX_DIGEST_COMPACT to the CexConfig file). \n
/// The Unrolled forms are optimized for speed and timing neutrality (suffix U), and the vertically vectorized functions have the V suffix. \n
/// The H suffix denotes functions that take an SIMD wrapper class (ULongXXX) as the state values, and process state in SIMD parallel blocks.</para>
/// <para>This class contains wide forms of the functions; PermuteR64P8x512H and PermuteR80P4x1024H use AVX2. \n
/// Experimental functions using AVX512 instructions are also implemented; PermuteR64P16x512H and PermuteR80P8x1024H. \n
/// These functions are not visible until run-time on some compiler platforms unless the compiler flag (__AVX2__ or __AVX512__) is explicitly declared.</para>
/// </summary>
class SHA2
{
private:

	static const std::vector<uint> SHA256_RC64;
	static const std::vector<ulong> SHA512_RC80;

	template<typename T>
	static void Round256W(T &A, T &B, T &C, T &D, T &E, T &F, T &G, T &H, T &M, T &P)
	{
		T R(H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) | (E << 7))) + ((E & F) ^ (~E & G)) + M + P);
		D += R;
		H = R + ((((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^ ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C)));
	}

	template<typename T>
	static void Round512W(T &A, T &B, T &C, T &D, T &E, T &F, T &G, T &H, T &M, T &P)
	{
		T R(H + (((E << 50) | (E >> 14)) ^ ((E << 46) | (E >> 18)) ^ ((E << 23) | (E >> 41))) + ((E & F) ^ (~E & G)) + M + P);
		D += R;
		H = R + (((A << 36) | (A >> 28)) ^ ((A << 30) | (A >> 34)) ^ ((A << 25) | (A >> 39))) + ((A & B) ^ (A & C) ^ (B & C));
	}

	template<typename T>
	inline static T Sigma0(T &X)
	{
		return (((X << 63) | (X >> 1)) ^ ((X << 56) | (X >> 8)) ^ (X >> 7));
	}

	template<typename T>
	inline static T Sigma1(T &X)
	{
		return (((X << 45) | (X >> 19)) ^ ((X << 3) | (X >> 61)) ^ (X >> 6));
	}

	template<typename T>
	inline static T Theta0(T &X)
	{
		return T(((X >> 7) | (X << 25)) ^ ((X >> 18) | (X << 14)) ^ (X >> 3));
	}

	template<typename T>
	inline static T Theta1(T &X)
	{
		return T(((X >> 17) | (X << 15)) ^ ((X >> 19) | (X << 13)) ^ (X >> 10));
	}

	static void Round256(uint A, uint B, uint C, uint &D, uint E, uint F, uint G, uint &H, uint M, uint P);
	static void Round512(ulong A, ulong B, ulong C, ulong &D, ulong E, ulong F, ulong G, ulong &H, ulong M, ulong P);

public:

	static const std::vector<uint> SHA256State;
	static const std::vector<ulong> SHA384State;
	static const std::vector<ulong> SHA512State;

	static const size_t SHA256_DIGEST_SIZE = 32;
	static const size_t SHA384_DIGEST_SIZE = 48;
	static const size_t SHA512_DIGEST_SIZE = 64;
	static const size_t SHA256_RATE_SIZE = 64;
	static const size_t SHA384_RATE_SIZE = 128;
	static const size_t SHA512_RATE_SIZE = 128;

	//~~~SHA2-256~~~//

	/// <summary>
	/// A compact (stateless) form of the SHA2-256 message digest function; processes a message, and return the hash in the output array.
	/// </summary>
	/// 
	/// <param name="Input">The input byte message array, can be either a standard array or vector</param>
	/// <param name="InOffset">The starting offseet within the input byte array</param>
	/// <param name="InLength">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; contains the output hash of 32 bytes</param>
	/// <param name="OutOffset">The starting offseet within the output byte array</param>
	template<typename ArrayU8>
	static void Compute256(const ArrayU8 &Input, size_t InOffset, size_t InLength, ArrayU8 &Output, size_t OutOffset)
	{
		std::array<uint, 8> state = { 0 };
		std::vector<byte> buf(SHA256_RATE_SIZE);
		ulong bitlen;
		ulong t;

		t = 0;
		MemoryTools::Copy(SHA256State, 0, state, 0, state.size() * sizeof(uint));

		while (InLength >= SHA256_RATE_SIZE)
		{
			PermuteR64P512U(Input, InOffset, state);
			InLength -= SHA256_RATE_SIZE;
			InOffset += SHA256_RATE_SIZE;
			t += SHA256_RATE_SIZE;
		}

		t += InLength;
		bitlen = (t << 3);
		MemoryTools::Copy(Input, InOffset, buf, 0, InLength);

		buf[InLength] = 128;
		++InLength;

		if (InLength > 56)
		{
			PermuteR64P512U(buf, 0, state);
			MemoryTools::Clear(buf, 0, SHA256_RATE_SIZE);
		}

		IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitlen) >> 32), buf, 56);
		IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitlen)), buf, 60);

		PermuteR64P512U(buf, 0, state);

		// copy as big endian aligned to output code
		IntegerTools::BeUL256ToBlock(state, 0, Output, OutOffset);
	}

	/// <summary>
	/// A compact (stateless) form of the SHA2-256 message authentication code generator (HMAC-256).
	/// <para>Process a key, and a message, and return the hash in the output array.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input byte key array, can be either a standard array or vector</param>
	/// <param name="Input">The input byte message array, can be either a standard array or vector</param>
	/// <param name="InOffset">The starting offseet within the message byte array</param>
	/// <param name="InLength">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; contains the output mac code of 32 bytes</param>
	/// <param name="OutOffset">The starting offseet within the output byte array</param>
	template<typename ArrayU8>
	static void MACR64P512(const ArrayU8 &Key, const ArrayU8 &Input, size_t InOffset, size_t InLength, ArrayU8 &Output, size_t OutOffset)
	{
		CEXASSERT(Key.size() <= SHA256_RATE_SIZE, "The Mac key array must be a maximum of 64 bytes in length");

		const byte IPAD = 0x36;
		const byte OPAD = 0x5C;
		std::vector<byte> buf(SHA256_RATE_SIZE);
		std::vector<byte> ipad(SHA256_RATE_SIZE);
		std::vector<byte> opad(SHA256_RATE_SIZE);
		std::array<uint, 8> state = { 0 };
		ulong bitlen;
		ulong t;

		// copy in the key and xor the hamming weights into input and output pads
		MemoryTools::Copy(Key, 0, ipad, 0, Key.size());
		MemoryTools::Copy(ipad, 0, opad, 0, ipad.size());
		MemoryTools::XorPad(ipad, IPAD);
		MemoryTools::XorPad(opad, OPAD);

		// initialize the sha256 state
		MemoryTools::Copy(SHA256State, 0, state, 0, state.size() * sizeof(uint));

		// permute the input pad
		PermuteR64P512U(ipad, 0, state);
		t = SHA256_RATE_SIZE;

		// process the message
		while (InLength >= SHA256_RATE_SIZE)
		{
			PermuteR64P512U(Input, InOffset, state);
			InLength -= SHA256_RATE_SIZE;
			InOffset += SHA256_RATE_SIZE;
			t += SHA256_RATE_SIZE;
		}

		// finalize the message data
		t += InLength;
		bitlen = (t << 3);
		MemoryTools::Copy(Input, InOffset, buf, 0, InLength);
		buf[InLength] = 128;
		++InLength;

		if (InLength > 56)
		{
			PermuteR64P512U(buf, 0, state);
			MemoryTools::Clear(buf, 0, SHA256_RATE_SIZE);
		}

		IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitlen) >> 32), buf, 56);
		IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitlen)), buf, 60);
		PermuteR64P512U(buf, 0, state);

		// store the code in the buffer
		IntegerTools::BeUL256ToBlock(state, 0, buf, 0);
		MemoryTools::Clear(buf, SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
		// reset the sha2 state
		MemoryTools::Copy(SHA256State, 0, state, 0, state.size() * sizeof(uint));

		// permute the output pad
		PermuteR64P512U(opad, 0, state);
		// finalize the buffer
		t = SHA256_RATE_SIZE + SHA256_DIGEST_SIZE;
		bitlen = (t << 3);
		buf[SHA256_DIGEST_SIZE] = 128;
		IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitlen) >> 32), buf, 56);
		IntegerTools::Be32ToBytes(static_cast<uint>(static_cast<ulong>(bitlen)), buf, 60);
		PermuteR64P512U(buf, 0, state);

		// copy as big endian aligned to output code
		IntegerTools::BeUL256ToBlock(state, 0, Output, OutOffset);
	}

	/// <summary>
	/// The compact form of the SHA2-256 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR64P512C(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State);

	/// <summary>
	/// The unrolled form of the SHA2-256 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR64P512U(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State);

	/// <summary>
	/// The vertically vectorized form of the SHA2-256 permutation function.
	/// <para>This function uses the Intel SHA-NI instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR64P512V(const std::vector<byte> &Input, size_t InOffset, std::array<uint, 8> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-256 permutation function.
	/// <para>This function processes 8*64 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt256 state array</param>
	static void PermuteR64P8x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt256> &State);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-256 permutation function.
	/// <para>This function process 16*64 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	static void PermuteR64P16x512H(const std::vector<byte> &Input, size_t InOffset, std::vector<UInt512> &State);

#endif

	//~~~SHA2-384~~~//

	/// <summary>
	/// A compact (stateless) form of the SHA2-384 message digest function; processes a message, and return the hash in the output array.
	/// </summary>
	/// 
	/// <param name="Input">The input byte message array, can be either a standard array or vector</param>
	/// <param name="InOffset">The starting offseet within the input byte array</param>
	/// <param name="InLength">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; containst the output hash of 48 bytes</param>
	/// <param name="OutOffset">The starting offseet within the output byte array</param>
	template<typename ArrayU8>
	static void Compute384(const ArrayU8 &Input, size_t InOffset, size_t InLength, ArrayU8 &Output, size_t OutOffset)
	{
		std::array<ulong, 8> state = { 0 };
		std::vector<byte> buf(SHA384_RATE_SIZE);
		ulong bitlen;
		std::array<ulong, 2> t = { 0 };

		MemoryTools::Copy(SHA384State, 0, state, 0, state.size() * sizeof(ulong));

		while (InLength >= SHA384_RATE_SIZE)
		{
			PermuteR80P1024U(Input, InOffset, state);
			InLength -= SHA384_RATE_SIZE;
			InOffset += SHA384_RATE_SIZE;
			t[0] += SHA384_RATE_SIZE;
		}

		t[0] += InLength;
		bitlen = (t[0] << 3);
		MemoryTools::Copy(Input, InOffset, buf, 0, InLength);

		buf[InLength] = 128;
		++InLength;

		if (InLength > 112)
		{
			PermuteR80P1024U(buf, 0, state);
			MemoryTools::Clear(buf, 0, SHA384_RATE_SIZE);
		}

		IntegerTools::Be64ToBytes(t[1], buf, 112);
		IntegerTools::Be64ToBytes(bitlen, buf, 120);

		PermuteR80P1024U(buf, 0, state);

		// copy as big endian aligned to output code
		IntegerTools::Be64ToBytes(state[0], Output, OutOffset);
		IntegerTools::Be64ToBytes(state[1], Output, OutOffset + 8);
		IntegerTools::Be64ToBytes(state[2], Output, OutOffset + 16);
		IntegerTools::Be64ToBytes(state[3], Output, OutOffset + 24);
		IntegerTools::Be64ToBytes(state[4], Output, OutOffset + 32);
		IntegerTools::Be64ToBytes(state[5], Output, OutOffset + 40);
	}

	//~~~SHA2-512~~~//

	/// <summary>
	/// A compact (stateless) form of the SHA2-512 message digest function; processes a message, and return the hash in the output array.
	/// </summary>
	/// 
	/// <param name="Input">The input byte message array, can be either a standard array or vector</param>
	/// <param name="InOffset">The starting offseet within the input byte array</param>
	/// <param name="InLength">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; containst the output hash of 64 bytes</param>
	/// <param name="OutOffset">The starting offseet within the output byte array</param>
	template<typename ArrayU8>
	static void Compute512(const ArrayU8 &Input, size_t InOffset, size_t InLength, ArrayU8 &Output, size_t OutOffset)
	{
		std::array<ulong, 8> state = { 0 };
		std::vector<byte> buf(SHA512_RATE_SIZE);
		ulong bitlen;
		std::array<ulong, 2> t = { 0 };

		MemoryTools::Copy(SHA512State, 0, state, 0, state.size() * sizeof(ulong));

		while (InLength >= SHA512_RATE_SIZE)
		{
			PermuteR80P1024U(Input, InOffset, state);
			InLength -= SHA512_RATE_SIZE;
			InOffset += SHA512_RATE_SIZE;
			t[0] += SHA512_RATE_SIZE;
		}

		t[0] += InLength;
		bitlen = (t[0] << 3);
		MemoryTools::Copy(Input, InOffset, buf, 0, InLength);

		buf[InLength] = 128;
		++InLength;

		if (InLength > 112)
		{
			PermuteR80P1024U(buf, 0, state);
			MemoryTools::Clear(buf, 0, SHA512_RATE_SIZE);
		}

		IntegerTools::Be64ToBytes(t[1], buf, 112);
		IntegerTools::Be64ToBytes(bitlen, buf, 120);

		PermuteR80P1024U(buf, 0, state);

		// copy as big endian aligned to output code
		IntegerTools::BeULL512ToBlock(state, 0, Output, OutOffset);
	}

	/// <summary>
	/// A compact (stateless) form of the HMAC SHA2-512 message authentication code generator (HMAC-512).
	/// <para>Process a key, and a message, and return the hash in the output array.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input byte key array, can be either a standard array or vector</param>
	/// <param name="Input">The input byte message array, can be either a standard array or vector</param>
	/// <param name="InOffset">The starting offseet within the message byte array</param>
	/// <param name="InLength">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; contains the output mac code of 64 bytes</param>
	/// <param name="OutOffset">The starting offseet within the output byte array</param>
	template<typename ArrayU8>
	static void MACR80P1024(const ArrayU8 &Key, const ArrayU8 &Input, size_t InOffset, size_t InLength, ArrayU8 &Output, size_t OutOffset)
	{
		CEXASSERT(Key.size() <= SHA512_RATE_SIZE, "The Mac key array must be a maximum of 128 bytes in length");

		const byte IPAD = 0x36;
		const byte OPAD = 0x5C;
		std::vector<byte> buf(SHA512_RATE_SIZE);
		std::vector<byte> ipad(SHA512_RATE_SIZE);
		std::vector<byte> opad(SHA512_RATE_SIZE);
		std::array<ulong, 8> state = { 0 };
		std::array<ulong, 2> t = { 0 };
		ulong bitlen;

		// copy in the key and xor the hamming weights into input and output pads
		MemoryTools::Copy(Key, 0, ipad, 0, Key.size());
		MemoryTools::Copy(ipad, 0, opad, 0, ipad.size());
		MemoryTools::XorPad(ipad, IPAD);
		MemoryTools::XorPad(opad, OPAD);

		// initialize the sha256 state
		MemoryTools::Copy(SHA512State, 0, state, 0, state.size() * sizeof(ulong));

		// permute the input pad
		PermuteR80P1024U(ipad, 0, state);
		t[0] = SHA512_RATE_SIZE;

		// process the message
		while (InLength >= SHA512_RATE_SIZE)
		{
			PermuteR80P1024U(Input, InOffset, state);
			InLength -= SHA512_RATE_SIZE;
			InOffset += SHA512_RATE_SIZE;
			t[0] += SHA512_RATE_SIZE;
		}

		// finalize the message data
		t[0] += InLength;
		bitlen = (t[0] << 3);
		MemoryTools::Copy(Input, InOffset, buf, 0, InLength);
		buf[InLength] = 128;
		++InLength;

		if (InLength > 112)
		{
			PermuteR80P1024U(buf, 0, state);
			MemoryTools::Clear(buf, 0, SHA512_RATE_SIZE);
		}

		IntegerTools::Be64ToBytes(t[1], buf, 112);
		IntegerTools::Be64ToBytes(bitlen, buf, 120);
		PermuteR80P1024U(buf, 0, state);

		// store the code in the buffer
		IntegerTools::BeULL512ToBlock(state, 0, buf, 0);
		MemoryTools::Clear(buf, SHA512_DIGEST_SIZE, SHA512_DIGEST_SIZE);
		// reset the sha2 state
		MemoryTools::Copy(SHA512State, 0, state, 0, state.size() * sizeof(ulong));

		// permute the output pad
		PermuteR80P1024U(opad, 0, state);
		// finalize the buffer
		t[0] = SHA512_RATE_SIZE + SHA512_DIGEST_SIZE;
		bitlen = (t[0] << 3);
		buf[SHA512_DIGEST_SIZE] = 128;
		IntegerTools::Be64ToBytes(t[1], buf, 112);
		IntegerTools::Be64ToBytes(bitlen, buf, 120);
		PermuteR80P1024U(buf, 0, state);

		// copy as big endian aligned to output code
		IntegerTools::BeULL512ToBlock(state, 0, Output, OutOffset);
	}

	/// <summary>
	/// The compact form of the SHA2-512 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR80P1024C(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State);

	/// <summary>
	/// The unrolled form of the SHA2-512 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR80P1024U(const std::vector<byte> &Input, size_t InOffset, std::array<ulong, 8> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-512 permutation function.
	/// <para>This function processes 4*128 blocks of input in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations state array</param>
	static void PermuteR80P4x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong256> &State);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized form of the SHA2-512 permutation function.
	/// <para>This function process 8*128 blocks of input in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="State">The permutations UInt512 state array</param>
	static void PermuteR80P8x1024H(const std::vector<byte> &Input, size_t InOffset, std::vector<ULong512> &State);

#endif
};

NAMESPACE_DIGESTEND
#endif
