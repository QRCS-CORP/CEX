// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2020 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITStateOUT ANY WARRANTY; without even the implied warranty of
// MERCStateANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_KECCAK_H
#define CEX_KECCAK_H

#include "CexDomain.h"
#include "IntegerTools.h"
#include "MemoryTools.h"

#if defined(__AVX2__)
#	include "ULong256.h"
#endif
#if defined(__AVX512__)
#	include "ULong512.h"
#endif

NAMESPACE_DIGEST

using Utility::IntegerTools;
using Utility::MemoryTools;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

/// <summary>
/// Internal static class containing the 24 and 48 round Keccak permutation functions.
/// <para>The function names are in the format; Permute-rounds-bits-suffix, ex. PermuteR24P1600C, 24 rounds, permutes 1600 bits, using the compact form of the function. \n
/// Note: The PermuteR48P1600U is an extended permutation function that uses 48 rounds, rather than the 24 rounds used by the standard implementation of Keccak. \n
/// The additional 24 rounds constants were generated using the LFSR from the Keccak code package, with the additional 24 constants being \n
/// the next in sequence generated by that LFSR.</para>
/// <para>The compact forms of the permutations have the suffix C, and are optimized for low memory consumption 
/// (enabled in the hash function by adding the CEX_DIGEST_COMPACT to the CexConfig file). \n
/// The Unrolled forms are optimized for speed and timing neutrality have the U suffix. \n
/// The H suffix denotes functions that take an SIMD wrapper class as the state values, and process message blocks in SIMD parallel blocks.</para>
/// <para>This class contains wide forms of the functions; PermuteR24P4x1600H and PermuteR48P4x1600H use AVX2. \n
/// Experimental functions using AVX512 instructions are also implemented; PermuteR24P8x1600H and PermuteR48P8x1600H. \n
/// These extended functions are only visible at run-time on some development platforms (VS..), if the __AVX2__ or __AVX512__ compiler flags are declared explicitly.</para>
/// </summary>
class Keccak
{
// Keccak 1024 round constants enum:
// Generated using the InitializeRoundConstants/LFSR86540 function from the keccak code package:
// https://github.com/gvanas/KeccakCodePackage/blob/aa3cded0ae844dbff0dbecfb6d42d50c7bdb9d9b/SnP/KeccakP-1600/Reference/KeccakP-1600-reference.c
// The first 24 are the standard constants, the second set was generated by extending the LFSR to generate 48 round constants
//const ulong RC[48] =
//{
//	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
//	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
//	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
//	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
//	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
//	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
//  // next sequence generated using LFSR86540
//	0x8000000080008082, 0x800000008000800A, 0x8000000000000003, 0x8000000080000009,
//	0x8000000000008082, 0x0000000000008009, 0x8000000000000080, 0x0000000000008083,
//	0x8000000000000081, 0x0000000000000001, 0x000000000000800B, 0x8000000080008001,
//	0x0000000000000080, 0x8000000000008000, 0x8000000080008001, 0x0000000000000009,
//	0x800000008000808B, 0x0000000000000081, 0x8000000000000082, 0x000000008000008B,
//	0x8000000080008009, 0x8000000080000000, 0x0000000080000080, 0x0000000080008003
//};

public:

	/// <summary>
	/// The round constants for the standard 24-round implementation of the Keccak permutation
	/// </summary>
	static const std::array<ulong, 24> KECCAK_RC24;

	/// <summary>
	/// The round constants for the extended 48-round implementation of the Keccak permutation
	/// </summary>
	static const std::array<ulong, 48> KECCAK_RC48;

	/// <summary>
	/// The Keccak cSHAKE domain identifier
	/// </summary>
	static const byte KECCAK_CSHAKE_DOMAIN = 0x04;

	/// <summary>
	/// The Keccak KMAC domain identifier
	/// </summary>
	static const byte KECCAK_KMAC_DOMAIN = 0x04;

	/// <summary>
	/// The Keccak SHA3 digest domain identifier
	/// </summary>
	static const byte KECCAK_SHA3_DOMAIN = 0x06;

	/// <summary>
	/// The Keccak SHAKE domain identifier
	/// </summary>
	static const byte KECCAK_SHAKE_DOMAIN = 0x1F;

	/// <summary>
	/// The Keccak custom 4x-wide cSHAKE domain identifier
	/// </summary>
	static const byte KECCAK_CSHAKEW4_DOMAIN = 0x21;

	/// <summary>
	/// The Keccak custom 8x-wide cSHAKE domain identifier
	/// </summary>
	static const byte KECCAK_CSHAKEW8_DOMAIN = 0x22;

	/// <summary>
	/// The SHA3-128 digest output hash size in bytes
	/// </summary>
	static const size_t KECCAK128_DIGEST_SIZE = 16;

	/// <summary>
	/// The SHA3-256 digest output hash size in bytes
	/// </summary>
	static const size_t KECCAK256_DIGEST_SIZE = 32;

	/// <summary>
	/// The SHA3-512 digest output hash size in bytes
	/// </summary>
	static const size_t KECCAK512_DIGEST_SIZE = 64;

	/// <summary>
	/// The SHA3-1024 digest output hash size in bytes
	/// </summary>
	static const size_t KECCAK1024_DIGEST_SIZE = 128;

	/// <summary>
	/// The Keccak-128 input rate size in bytes
	/// </summary>
	static const size_t KECCAK128_RATE_SIZE = 168;

	/// <summary>
	/// The Keccak-256 input rate size in bytes
	/// </summary>
	static const size_t KECCAK256_RATE_SIZE = 136;

	/// <summary>
	/// The Keccak-512 input rate size in bytes
	/// </summary>
	static const size_t KECCAK512_RATE_SIZE = 72;

	/// <summary>
	/// The Keccak-1024 input rate size in bytes
	/// </summary>
#if defined CEX_KECCAK_STRONG
	static const size_t KECCAK1024_RATE_SIZE = 36;
#else
	static const size_t KECCAK1024_RATE_SIZE = 72;
#endif

	/// <summary>
	/// The Keccak state size in uint64 integers
	/// </summary>
	static const size_t KECCAK_STATE_SIZE = 25;

	/// <summary>
	/// The Keccak 24-round absorb function; copy bytes from a byte array to the state array.
	/// <para>Input length must be 64-bit aligned, domain code terminates the input.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte array, can be either an 8-bit array or vector</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="InLength">The number of bytes to process; must be 64-bit aligned</param>
	/// <param name="Rate">The Keccak aborbtion rate in bytes</param>
	/// <param name="Domain">The Keccak implementation domain</param>
	/// <param name="State">The permutations uint64 state array</param>
	template<typename ArrayU8>
	static void AbsorbR24(const ArrayU8 &Input, size_t InOffset, size_t InLength, size_t Rate, byte Domain, std::array<ulong, KECCAK_STATE_SIZE> &State)
	{
		std::array<byte, KECCAK_STATE_SIZE * sizeof(ulong)> msg = { 0 };

		while (InLength >= Rate)
		{
			Keccak::FastAbsorb(Input, InOffset, Rate, State);

#if defined(CEX_DIGEST_COMPACT)
			Keccak::PermuteR24P1600C(State);
#else
			Keccak::PermuteR24P1600U(State);
#endif

			InLength -= Rate;
			InOffset += Rate;
		}

		MemoryTools::Copy(Input, InOffset, msg, 0, InLength);
		msg[InLength] = Domain;
		msg[Rate - 1] |= 128;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::XOR(msg, 0, State, 0, Rate);
#else
		for (i = 0; i < (Rate >> 3); ++i)
		{
			State[i] ^= IntegerTools::LeBytesTo64(msg, (8 * i));
		}
#endif
	}

	/// <summary>
	/// The Keccak 48-round absorb function; copy bytes from a byte array to the state array.
	/// <para>Input length must be 64-bit aligned, domain code terminates the input.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte array, can be either an 8-bit array or vector</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="InLength">The number of bytes to process; must be 64-bit aligned</param>
	/// <param name="Rate">The Keccak aborbtion rate in bytes</param>
	/// <param name="Domain">The Keccak implementation domain</param>
	/// <param name="State">The permutations uint64 state array</param>
	template<typename ArrayU8>
	static void AbsorbR48(const ArrayU8 &Input, size_t InOffset, size_t InLength, size_t Rate, byte Domain, std::array<ulong, KECCAK_STATE_SIZE> &State)
	{
		std::array<byte, KECCAK_STATE_SIZE * sizeof(ulong)> msg = { 0 };

		while (InLength >= Rate)
		{
			Keccak::FastAbsorb(Input, InOffset, Rate, State);

#if defined(CEX_DIGEST_COMPACT)
			Keccak::PermuteR48P1600C(State);
#else
			Keccak::PermuteR48P1600U(State);
#endif

			InLength -= Rate;
			InOffset += Rate;
		}

		MemoryTools::Copy(Input, InOffset, msg, 0, InLength);
		msg[InLength] = Domain;
		msg[Rate - 1] |= 128;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::XOR(msg, 0, State, 0, Rate);
#else
		for (i = 0; i < (Rate >> 3); ++i)
		{
			State[i] ^= IntegerTools::LeBytesTo64(msg, (8 * i));
		}
#endif
	}

	/// <summary>
	/// A compact (stateless) form of the Keccak message digest function (SHA3) using the standard 24 rounds; processes a message, and return the hash in the output array.
	/// <para>Set the Rate parameter to match the desired SHA3 function; 128, 256, or 512-bit hash function.</para>
	/// </summary>
	/// 
	/// <param name="Message">The input byte message array, can be either a standard array or vector</param>
	/// <param name="Offset">The starting offseet within the message byte array</param>
	/// <param name="Length">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; returns a hash the size of the SHA3 mode, set by the Rate parameter; 16, 32, or 64 bytes</param>
	/// <param name="Rate">The block input rate of permutation calls; SHAKE128=168, SHAKE256=136, SHAKE512=72</param>
	template<typename ArrayU8>
	static void Compute(const ArrayU8 &Message, size_t Offset, size_t Length, ArrayU8 &Output, size_t Rate)
	{
		std::array<ulong, KECCAK_STATE_SIZE> state = { 0 };
		ArrayU8 hash(KECCAK256_DIGEST_SIZE);
		const size_t OTPLEN = ((KECCAK_STATE_SIZE * sizeof(ulong)) - Rate) / 2;

		AbsorbR24(Message, Offset, Length, Rate, KECCAK_SHA3_DOMAIN, state);

#if defined(CEX_DIGEST_COMPACT)
		Keccak::PermuteR24P1600C(state);
#else
		Keccak::PermuteR24P1600U(state);
#endif

		MemoryTools::Copy(state, 0, Output, 0, OTPLEN);
	}

	/// <summary>
	/// The standard 24 round implementation used by custom SHAKE functions to add customization and name strings to the state
	/// </summary>
	/// 
	/// <param name="Customization">The input byte message array, can be either a standard array or vector</param>
	/// <param name="Name">The starting offseet within the message byte array</param>
	/// <param name="Rate">The block input rate of permutation calls; SHAKE128=168, SHAKE256=136, SHAKE512=72</param>
	/// <param name="State">The permutations uint64 state array</param>
	template<typename ArrayU8>
	static void CustomizeR24(const ArrayU8 &Customization, const ArrayU8 &Name, size_t Rate, std::array<ulong, KECCAK_STATE_SIZE> &State)
	{
		const size_t BUFFER_SIZE = KECCAK_STATE_SIZE * sizeof(ulong);
		std::array<byte, BUFFER_SIZE> pad = { 0 };
		size_t i;
		size_t offset;

		offset = Keccak::LeftEncode(pad, 0, static_cast<ulong>(Rate));
		offset += Keccak::LeftEncode(pad, offset, static_cast<ulong>(Name.size()) * 8);

		if (Name.size() != 0)
		{
			for (i = 0; i < Name.size(); ++i)
			{
				if (offset == Rate)
				{
					Keccak::FastAbsorb(pad, 0, Rate, State);
					PermuteR24P1600U(State);
					offset = 0;
				}

				pad[offset] = Name[i];
				++offset;
			}
		}

		offset += Keccak::LeftEncode(pad, offset, static_cast<ulong>(Customization.size()) * 8);

		if (Customization.size() != 0)
		{
			for (i = 0; i < Customization.size(); ++i)
			{
				if (offset == Rate)
				{
					Keccak::FastAbsorb(pad, 0, Rate, State);
					PermuteR24P1600U(State);
					offset = 0;
				}

				pad[offset] = Customization[i];
				++offset;
			}
		}

		MemoryTools::Clear(pad, offset, BUFFER_SIZE - offset);
		offset = (offset % sizeof(ulong) == 0) ? offset : offset + (sizeof(ulong) - (offset % sizeof(ulong)));
		MemoryTools::XOR(pad, 0, State, 0, offset);

		PermuteR24P1600U(State);
	}

	/// <summary>
	/// The extended 48 round implementation used by custom SHAKE functions to add customization and name strings to the state
	/// </summary>
	/// 
	/// <param name="Customization">The input byte message array, can be either a standard array or vector</param>
	/// <param name="Name">The starting offseet within the message byte array</param>
	/// <param name="Rate">The block input rate of permutation calls; SHAKE128=168, SHAKE256=136, SHAKE512=72</param>
	/// <param name="State">The permutations uint64 state array</param>
	template<typename ArrayU8>
	static void CustomizeR48(const ArrayU8 &Customization, const ArrayU8 &Name, size_t Rate, std::array<ulong, KECCAK_STATE_SIZE> &State)
	{
		const size_t BUFFER_SIZE = KECCAK_STATE_SIZE * sizeof(ulong);
		std::array<byte, BUFFER_SIZE> pad = { 0 };
		size_t i;
		size_t offset;

		offset = Keccak::LeftEncode(pad, 0, static_cast<ulong>(Rate));
		offset += Keccak::LeftEncode(pad, offset, static_cast<ulong>(Name.size()) * 8);

		if (Name.size() != 0)
		{
			for (i = 0; i < Name.size(); ++i)
			{
				if (offset == Rate)
				{
					Keccak::FastAbsorb(pad, 0, Rate, State);
					PermuteR48P1600U(State);
					offset = 0;
				}

				pad[offset] = Name[i];
				++offset;
			}
		}

		offset += Keccak::LeftEncode(pad, offset, static_cast<ulong>(Customization.size()) * 8);

		if (Customization.size() != 0)
		{
			for (i = 0; i < Customization.size(); ++i)
			{
				if (offset == Rate)
				{
					Keccak::FastAbsorb(pad, 0, Rate, State);
					PermuteR48P1600U(State);
					offset = 0;
				}

				pad[offset] = Customization[i];
				++offset;
			}
		}

		MemoryTools::Clear(pad, offset, BUFFER_SIZE - offset);
		offset = (offset % sizeof(ulong) == 0) ? offset : offset + (sizeof(ulong) - (offset % sizeof(ulong)));
		MemoryTools::XOR(pad, 0, State, 0, offset);

		PermuteR48P1600U(State);
	}

	/// <summary>
	/// The Keccak custom XOF function (cSHAKE) using the standard 24 rounds; process a key, customization and name strings and return a pseudo-random output array.
	/// <para>A compact form of the cSHAKE XOF function.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input byte key array, can be either a standard array or vector</param>
	/// <param name="Customization">The customization string; can be used to create a custom implementation of SHAKE</param>
	/// <param name="Name">The name string, optional; can be used to as a domain or algorithm identifier, creating unique output</param>
	/// <param name="Output">The input byte seed array, can be either an 8-bit array or vector</param>
	/// <param name="Offset">The starting offset withing the output array</param>
	/// <param name="Length">The number of output bytes to produce</param>
	/// <param name="Rate">The block input rate of permutation calls; SHAKE128=168, SHAKE256=136, SHAKE512=72</param>
	template<typename ArrayU8>
	static void CXOFR24P1600(const ArrayU8 &Key, const ArrayU8 &Customization, const ArrayU8 &Name, ArrayU8 &Output, size_t Offset, size_t Length, size_t Rate)
	{
		std::array<ulong, KECCAK_STATE_SIZE> state = { 0 };
		CustomizeR24(Customization, Name, Rate, state);
		AbsorbR24(Key, 0, Key.size(), Rate, Keccak::KECCAK_CSHAKE_DOMAIN, state);

		while (Length != 0)
		{
			const size_t DIFF = IntegerTools::Min(Rate, Length);

			PermuteR24P1600U(state);
			MemoryTools::Copy(state, 0, Output, Offset, DIFF);
			Offset += DIFF;
			Length -= DIFF;
		}
	}

	/// <summary>
	/// The extended Keccak custom XOF function (cSHAKE) using 48 rounds; process an input seed array and return a pseudo-random output array.
	/// <para>A compact form of the cSHAKE XOF function.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input byte key array, can be either a standard array or vector</param>
	/// <param name="Customization">The customization string; can be used to create a custom implementation of SHAKE</param>
	/// <param name="Name">The name string, optional; can be used to as a domain or algorithm identifier, creating unique output</param>
	/// <param name="Output">The input byte seed array, can be either an 8-bit array or vector</param>
	/// <param name="Offset">The starting offset withing the output array</param>
	/// <param name="Length">The number of output bytes to produce</param>
	/// <param name="Rate">The block input rate of permutation calls; SHAKE128=168, SHAKE256=136, SHAKE512=72</param>
	template<typename ArrayU8>
	static void CXOFPR481600(const ArrayU8 &Key, const ArrayU8 &Customization, const ArrayU8 &Name, ArrayU8 &Output, size_t Offset, size_t Length, size_t Rate)
	{
		std::array<ulong, KECCAK_STATE_SIZE> state = { 0 };
		CustomizeR48(Customization, Name, Rate, state);
		AbsorbR48(Key, 0, Key.size(), Rate, Keccak::KECCAK_CSHAKE_DOMAIN, state);

		while (Length != 0)
		{
			const size_t DIFF = IntegerTools::Min(Rate, Length);

			PermuteR48P1600U(state);
			MemoryTools::Copy(state, 0, Output, Offset, DIFF);
			Offset += DIFF;
			Length -= DIFF;
		}
	}

	/// <summary>
	/// The fast absorb function; XOR an input byte array with the state array, no other processing is performed.
	/// <para>Input length must be 64-bit aligned.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte array, can be either an 8-bit array or vector</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="InLength">The number of bytes to process; must be 64-bit aligned</param>
	/// <param name="State">The permutations uint64 state array</param>
	template<typename ArrayU8>
	static void FastAbsorb(const ArrayU8 &Input, size_t InOffset, size_t InLength, std::array<ulong, KECCAK_STATE_SIZE> &State)
	{
		CEXASSERT(InLength % sizeof(ulong) == 0, "The input length is not 64-bit aligned");

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::XOR(Input, InOffset, State, 0, InLength);
#else
		for (size_t i = 0; i < InLength / sizeof(ulong); ++i)
		{
			State[i] ^= IntegerTools::LeBytesTo64(Input, InOffset + (i * sizeof(ulong)));
		}
#endif
	}

	/// <summary>
	/// Keccak common function: Left encode a value onto an array
	/// </summary>
	/// 
	/// <param name="Output">The output integer array</param>
	/// <param name="Offset">The output array starting offest</param>
	/// <param name="Value">The value to remove</param>
	/// 
	/// <returns>The number of encoded bits</returns>
	template<typename ArrayU8>
	static ulong LeftEncode(ArrayU8 &Output, size_t Offset, ulong Value)
	{
		ulong i;
		ulong n;
		ulong v;

		for (v = Value, n = 0; v && (n < sizeof(ulong)); ++n, v >>= 8)
		{
		}

		if (n == 0)
		{
			n = 1;
		}

		for (i = 1; i <= n; ++i)
		{
			Output[Offset + i] = static_cast<uint8_t>(Value >> (8 * (n - i)));
		}

		Output[Offset] = static_cast<uint8_t>(n);

		return (n + 1);
	}

	/// <summary>
	/// A compact (stateless) form of the message authentication code generator (KMAC), using the standard 24 round permutation.
	/// <para>Process a key, customization string, and a message, and output a keyed-hash output array.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input byte key array, can be either a standard array or vector</param>
	/// <param name="Customization">The customization string; can be used to create a custom implementation of KMAC</param>
	/// <param name="Message">The input byte message array, can be either a standard array or vector</param>
	/// <param name="Offset">The starting offseet within the message byte array</param>
	/// <param name="Length">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; returns a hash the size of the KMAC mode, set by the Rate parameter; 16, 32, or 64 bytes</param>
	/// <param name="Rate">The block input rate of permutation calls; KMAC128=168, KMAC256=136, KMAC512=72</param>
	template<typename ArrayU8>
	static void MACR24P1600(const ArrayU8 &Key, const ArrayU8 &Customization, const ArrayU8 &Message, size_t Offset, size_t Length, ArrayU8 &Output, size_t Rate)
	{
		const size_t BUFLEN = Keccak::KECCAK_STATE_SIZE * sizeof(ulong);
		const std::vector<byte> KNAME{ 0x4B, 0x4D, 0x41, 0x43 };
		std::array<ulong, KECCAK_STATE_SIZE> state = { 0 };
		std::array<byte, BUFLEN> pad = { 0 };
		std::vector<byte> buf(sizeof(size_t) + 1);
		ulong poft;
		size_t blen;
		size_t i;

		// add the customization
		CustomizeR24(Customization, KNAME, Rate, state);
		
		// absorb the key
		poft = LeftEncode(pad, 0, static_cast<ulong>(Rate));
		poft += LeftEncode(pad, poft, static_cast<ulong>(Key.size()) * sizeof(ulong));

		if (Key.size() != 0)
		{
			for (i = 0; i < Key.size(); ++i)
			{
				if (poft == Rate)
				{
					FastAbsorb(pad, 0, Rate, state);
					PermuteR24P1600U(state);
					poft = 0;
				}

				pad[poft] = Key[i];
				++poft;
			}
		}

		MemoryTools::Clear(pad, poft, BUFLEN - poft);
		poft = (poft % sizeof(ulong) == 0) ? poft : poft + (sizeof(ulong) - (poft % sizeof(ulong)));

		for (i = 0; i < poft; i += 8)
		{
			state[i / sizeof(ulong)] ^= IntegerTools::LeBytesTo64(pad, i);
		}

		PermuteR24P1600U(state);

		// loop through the message, absorbing it into the state
		while (Length >= Rate)
		{
			FastAbsorb(Message, Offset, Rate, state);
			PermuteR24P1600U(state);
			Length -= Rate;
			Offset += Rate;
		}

		if (Length != 0)
		{
			MemoryTools::Copy(Message, Offset, pad, 0, Length);
			MemoryTools::Clear(pad, Length, pad.size() - Length);
		}

		// add the remaining message bytes to the state and finalize

		blen = Keccak::RightEncode(pad, Length, static_cast<ulong>(Output.size()) * sizeof(ulong));

		Length += blen;
		pad[Length] = Keccak::KECCAK_KMAC_DOMAIN;
		pad[Rate - 1] |= 128;
		Keccak::FastAbsorb(pad, 0, Rate, state);

		// output the hash
		Length = Output.size();
		Offset = 0;

		while (Length != 0)
		{
			const size_t DIFF = IntegerTools::Min(Rate, Length);
			PermuteR24P1600U(state);
			MemoryTools::Copy(state, 0, Output, Offset, DIFF);
			Offset += DIFF;
			Length -= DIFF;
		}
	}

	/// <summary>
	/// A compact (stateless) form of the message authentication code generator (KMAC), using the extended 48 round permutation.
	/// <para>Process a key, customization string, and a message, and output a keyed-hash output array.</para>
	/// </summary>
	/// 
	/// <param name="Key">The input byte key array, can be either a standard array or vector</param>
	/// <param name="Customization">The customization string; can be used to create a custom implementation of KMAC</param>
	/// <param name="Message">The input byte message array, can be either a standard array or vector</param>
	/// <param name="Offset">The starting offseet within the message byte array</param>
	/// <param name="Length">The number of message bytes to process</param>
	/// <param name="Output">The output hash array; returns a hash the size of the KMAC mode, set by the Rate parameter; 16, 32, or 64 bytes</param>
	/// <param name="Rate">The block input rate of permutation calls; KMAC128=168, KMAC256=136, KMAC512=72</param>
	template<typename ArrayU8>
	static void MACR48P1600(const ArrayU8 &Key, const ArrayU8 &Customization, const ArrayU8 &Message, size_t Offset, size_t Length, ArrayU8 &Output, size_t Rate)
	{
		const size_t BUFLEN = Keccak::KECCAK_STATE_SIZE * sizeof(ulong);
		const std::vector<byte> KNAME{ 0x4B, 0x4D, 0x41, 0x43 };
		std::array<ulong, KECCAK_STATE_SIZE> state = { 0 };
		std::array<byte, BUFLEN> pad = { 0 };
		std::vector<byte> buf(sizeof(size_t) + 1);
		ulong poft;
		size_t blen;
		size_t i;

		// add the customization
		CustomizeR48(Customization, KNAME, Rate, state);

		// absorb the key
		poft = LeftEncode(pad, 0, static_cast<ulong>(Rate));
		poft += LeftEncode(pad, poft, static_cast<ulong>(Key.size()) * sizeof(ulong));

		if (Key.size() != 0)
		{
			for (i = 0; i < Key.size(); ++i)
			{
				if (poft == Rate)
				{
					FastAbsorb(pad, 0, Rate, state);
					PermuteR48P1600U(state);
					poft = 0;
				}

				pad[poft] = Key[i];
				++poft;
			}
		}

		MemoryTools::Clear(pad, poft, BUFLEN - poft);
		poft = (poft % sizeof(ulong) == 0) ? poft : poft + (sizeof(ulong) - (poft % sizeof(ulong)));

		for (i = 0; i < poft; i += 8)
		{
			state[i / sizeof(ulong)] ^= IntegerTools::LeBytesTo64(pad, i);
		}

		PermuteR48P1600U(state);

		// loop through the message, absorbing it into the state
		while (Length >= Rate)
		{
			FastAbsorb(Message, Offset, Rate, state);
			PermuteR48P1600U(state);
			Length -= Rate;
			Offset += Rate;
		}

		if (Length != 0)
		{
			MemoryTools::Copy(Message, Offset, pad, 0, Length);
			MemoryTools::Clear(pad, Length, pad.size() - Length);
		}

		// add the remaining message bytes to the state and finalize

		blen = Keccak::RightEncode(pad, Length, static_cast<ulong>(Output.size()) * sizeof(ulong));

		Length += blen;
		pad[Length] = Keccak::KECCAK_KMAC_DOMAIN;
		pad[Rate - 1] |= 128;
		Keccak::FastAbsorb(pad, 0, Rate, state);

		// output the hash
		Length = Output.size();
		Offset = 0;

		while (Length != 0)
		{
			const size_t DIFF = IntegerTools::Min(Rate, Length);
			PermuteR48P1600U(state);
			MemoryTools::Copy(state, 0, Output, Offset, DIFF);
			Offset += DIFF;
			Length -= DIFF;
		}
	}

	/// <summary>
	/// The Keccak 24-round extraction function; extract blocks of state to an output 8-bit array
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	/// <param name="Output">The output byte array, can be either an 8-bit array or vector</param>
	/// <param name="OutOffset">The starting offset withing the output array</param>
	/// <param name="Blocks">The number of blocks to extract</param>
	/// <param name="Rate">The Keccak extraction rate</param>
	template<typename ArrayU8>
	static void SqueezeR24(std::array<ulong, KECCAK_STATE_SIZE> &State, ArrayU8 &Output, size_t OutOffset, size_t Blocks, size_t Rate)
	{
		while (Blocks > 0)
		{
			Keccak::PermuteR24P1600U(State);

#if defined(CEX_IS_LITTLE_ENDIAN)
			MemoryTools::Copy(State, 0, Output, OutOffset, Rate);
#else

			for (size_t i = 0; i < (Rate >> 3); i++)
			{
				IntegerTools::Le64ToBytes(State[i], Output, OutOffset + (8 * i));
			}
#endif

			OutOffset += Rate;
			--Blocks;
		}
	}

	/// <summary>
	/// The Keccak 48-round extraction function; extract blocks of state to an output 8-bit array
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	/// <param name="Output">The output byte array, can be either an 8-bit array or vector</param>
	/// <param name="OutOffset">The starting offset withing the output array</param>
	/// <param name="Blocks">The number of blocks to extract</param>
	/// <param name="Rate">The Keccak extraction rate</param>
	template<typename ArrayU8>
	static void SqueezeR48(std::array<ulong, KECCAK_STATE_SIZE> &State, ArrayU8 &Output, size_t OutOffset, size_t Blocks, size_t Rate)
	{
		while (Blocks > 0)
		{
			Digest::Keccak::PermuteR48P1600U(State);

#if defined(CEX_IS_LITTLE_ENDIAN)
			MemoryTools::Copy(State, 0, Output, OutOffset, Rate);
#else

			for (size_t i = 0; i < (Rate >> 3); i++)
			{
				IntegerTools::Le64ToBytes(State[i], Output, OutOffset + (8 * i));
			}
#endif

			OutOffset += Rate;
			--Blocks;
		}
	}

	/// <summary>
	/// The Keccak XOF function using 24 rounds; process an input seed array and return a pseudo-random output array.
	/// <para>A compact form of the SHAKE XOF function.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte seed array, can be either an 8-bit array or vector</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="InLength">The number of seed bytes to process</param>
	/// <param name="Output">The input byte seed array, can be either an 8-bit array or vector</param>
	/// <param name="OutOffset">The starting offset withing the output array</param>
	/// <param name="OutLength">The number of output bytes to produce</param>
	/// <param name="Rate">The block input rate of permutation calls; SHAKE128=168, SHAKE256=136, SHAKE512=72</param>
	template<typename ArrayU8A, typename ArrayU8B>
	static void XOFR24P1600(const ArrayU8A &Input, size_t InOffset, size_t InLength, ArrayU8B &Output, size_t OutOffset, size_t OutLength, size_t Rate)
	{
		std::array<byte, KECCAK_STATE_SIZE * sizeof(ulong)> msg = { 0 };
		std::array<ulong, KECCAK_STATE_SIZE> state = { 0 };
		size_t blkcnt;
		size_t i;

		while (InLength >= Rate)
		{
			FastAbsorb(Input, InOffset, Rate, state);
			PermuteR24P1600U(state);
			InLength -= Rate;
			InOffset += Rate;
		}

		MemoryTools::Copy(Input, InOffset, msg, 0, InLength);
		msg[InLength] = KECCAK_SHAKE_DOMAIN;
		MemoryTools::Clear(msg, InLength + 1, Rate - InLength + 1);
		msg[Rate - 1] |= 128;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::XOR(msg, 0, state, 0, Rate);
#else
		for (i = 0; i < (Rate >> 3); ++i)
		{
			state[i] ^= IntegerTools::LeBytesTo64(msg, (8 * i));
		}
#endif

		blkcnt = OutLength / Rate;
		SqueezeR24(state, Output, OutOffset, blkcnt, Rate);
		OutOffset += blkcnt * Rate;
		OutLength -= blkcnt * Rate;

		if (OutLength != 0)
		{
			PermuteR24P1600U(state);

			const size_t FNLBLK = (OutLength % sizeof(ulong) == 0) ? OutLength / sizeof(ulong) : OutLength / sizeof(ulong) + 1;

			for (i = 0; i < FNLBLK; i++)
			{
				IntegerTools::Le64ToBytes(state[i], msg, (8 * i));
			}

			MemoryTools::Copy(msg, 0, Output, OutOffset, OutLength);
		}
	}

	/// <summary>
	/// The extended Keccak XOF function using 48 rounds; process an input seed array and return a pseudo-random output array.
	/// <para>A compact form of the SHAKE XOF function.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input byte seed array, can be either an 8-bit array or vector</param>
	/// <param name="InOffset">The starting offset withing the input array</param>
	/// <param name="InLength">The number of seed bytes to process</param>
	/// <param name="Output">The input byte seed array, can be either an 8-bit array or vector</param>
	/// <param name="OutOffset">The starting offset withing the output array</param>
	/// <param name="OutLength">The number of output bytes to produce</param>
	/// <param name="Rate">The block input rate of permutation calls; SHAKE128=168, SHAKE256=136, SHAKE512=72</param>
	template<typename ArrayU8A, typename ArrayU8B>
	static void XOFR48P1600(const ArrayU8A &Input, size_t InOffset, size_t InLength, ArrayU8B &Output, size_t OutOffset, size_t OutLength, size_t Rate)
	{
		std::array<byte, KECCAK_STATE_SIZE * sizeof(ulong)> msg = { 0 };
		std::array<ulong, KECCAK_STATE_SIZE> state = { 0 };
		size_t blkcnt;
		size_t i;

		while (InLength >= Rate)
		{
			FastAbsorb(Input, InOffset, Rate, state);
			Keccak::PermuteR48P1600U(state);
			InLength -= Rate;
			InOffset += Rate;
		}

		MemoryTools::Copy(Input, InOffset, msg, 0, InLength);
		msg[InLength] = KECCAK_SHAKE_DOMAIN;
		MemoryTools::Clear(msg, InLength + 1, Rate - InLength + 1);
		msg[Rate - 1] |= 128;

#if defined(CEX_IS_LITTLE_ENDIAN)
		MemoryTools::XOR(msg, 0, state, 0, Rate);
#else
		for (i = 0; i < (Rate >> 3); ++i)
		{
			state[i] ^= IntegerTools::LeBytesTo64(msg, (8 * i));
		}
#endif

		blkcnt = OutLength / Rate;
		SqueezeR48(state, Output, OutOffset, blkcnt, Rate);
		OutOffset += blkcnt * Rate;
		OutLength -= blkcnt * Rate;

		if (OutLength != 0)
		{
			Keccak::PermuteR48P1600U(state);

			const size_t FNLBLK = (OutLength % sizeof(ulong) == 0) ? OutLength / sizeof(ulong) : OutLength / sizeof(ulong) + 1;

			for (i = 0; i < FNLBLK; ++i)
			{
				IntegerTools::Le64ToBytes(state[i], msg, (sizeof(ulong) * i));
			}

			MemoryTools::Copy(msg, 0, Output, OutOffset, OutLength);
		}
	}

	/// <summary>
	/// The compact form of the 24 round (standard) SHA3 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	static void PermuteR24P1600C(std::array<ulong, KECCAK_STATE_SIZE> &State);

	/// <summary>
	/// The unrolled form of the 24 round (standard) SHA3 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	static void PermuteR24P1600U(std::array<ulong, KECCAK_STATE_SIZE> &State);

	/// <summary>
	/// The compact form of the 48 round (extended) SHA3 permutation function.
	/// <para>This function has been optimized for a small memory consumption.
	/// To enable this function, add the CEX_DIGEST_COMPACT directive to the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	static void PermuteR48P1600C(std::array<ulong, KECCAK_STATE_SIZE> &State);

	/// <summary>
	/// The unrolled form of the 48 round (extended) SHA3 permutation function.
	/// <para>This function (the default) has been optimized for speed, and timing neutrality.
	/// To enable this function, remove the CEX_DIGEST_COMPACT directive from the CexConfig file.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations uint64 state array</param>
	static void PermuteR48P1600U(std::array<ulong, KECCAK_STATE_SIZE> &State);

#if defined(__AVX2__)

	/// <summary>
	/// The horizontally vectorized 24 round (standard) form of the SHA3 permutation function.
	/// <para>This function processes 4*25 blocks of state in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations ULong256 state array</param>
	static void PermuteR24P4x1600H(std::vector<ULong256> &State);

	/// <summary>
	/// The horizontally vectorized 48 round form (extended) of the SHA3 permutation function.
	/// <para>This function processes 4*25 blocks of state in parallel using AVX2 instructions.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations ULong256 state array</param>
	static void PermuteR48P4x1600H(std::vector<ULong256> &State);

#endif

#if defined(__AVX512__)

	/// <summary>
	/// The horizontally vectorized 24 round (standard) form of the SHA3 permutation function.
	/// <para>This function processes 8*25 blocks of state in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations ULong512 state array</param>
	static void PermuteR24P8x1600H(std::vector<ULong512> &State);

	/// <summary>
	/// The horizontally vectorized 48 round (extended) form of the SHA3 permutation function.
	/// <para>This function processes 8*25 blocks of state in parallel using AVX512 instructions.</para>
	/// </summary>
	/// 
	/// <param name="State">The permutations ULong512 state array</param>
	static void PermuteR48P8x1600H(std::vector<ULong512> &State);

#endif

	/// <summary>
	/// Keccak common function: Right encode a value onto an array
	/// </summary>
	/// 
	/// <param name="Output">The output integer array</param>
	/// <param name="Offset">The output array starting offest</param>
	/// <param name="Value">The value to remove</param>
	/// 
	/// <returns>The number of encoded bits</returns>
	template<typename Array>
	static ulong RightEncode(Array &Output, size_t Offset, ulong Value)
	{
		ulong i;
		ulong n;
		ulong v;

		for (v = Value, n = 0; v && (n < sizeof(ulong)); ++n, v >>= 8)
		{
		}

		if (n == 0)
		{
			n = 1;
		}

		for (i = 1; i <= n; ++i)
		{
			Output[Offset + (i - 1)] = static_cast<uint8_t>(Value >> (8 * (n - i)));
		}

		Output[Offset + n] = static_cast<uint8_t>(n);

		return n + 1;
	}
};

NAMESPACE_DIGESTEND
#endif
