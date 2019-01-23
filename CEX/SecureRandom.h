// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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
//
// 
// Implementation Details:
// An implementation of a Cryptographically Secure Pseudo Random Number Generator (SecureRandom). 
// Written by John Underhill, January 6, 2014
// Updated by December 1, 2016
// Contact: develop@vtdev.com

#ifndef CEX_SECURERANDOM_H
#define CEX_SECURERANDOM_H

#include "IProvider.h"
#include "CryptoRandomException.h"
#include "Drbgs.h"
#include "IDigest.h"
#include "IntegerTools.h"
#include "IPrng.h"
#include "MemoryTools.h"

NAMESPACE_PRNG

using Exception::CryptoRandomException;
using Enumeration::Digests;
using Prng::IPrng;
using Enumeration::Prngs;
using Enumeration::Providers;
using Provider::IProvider;

/// <summary>
/// An implementation of a cryptographically secure pseudo-random number generator.
/// </summary>
///
/// <remarks>
/// <para>This class is an extension wrapper that uses one of the PRNG and random provider implementations. \n
/// The PRNG and random provider type names are loaded through the constructor, instantiating internal instances of those classes and auto-initializing the base PRNG. \n
/// The default configuration uses and AES-256 CTR mode generator (BCR), and the auto seed collection provider. \n
/// The secure random class can use any combination of the base PRNGs and random providers. \n
/// Note* as of version 1.0.0.2, the order of the Minimum and Maximum parameters on the NextIntXX api has changed, it is now with the Maximum parameter first, ex. NextInt16(max, min).</para>
/// </remarks>
/// 
/// <example>
/// <c>
/// SecureRandom rnd;
/// int x = rnd.NextInt32();
/// </c>
/// </example>
class SecureRandom
{
private:

	static const std::string CLASS_NAME;
	static const size_t DEF_BUFLEN = 4096;

	size_t m_bufferIndex;
	size_t m_bufferSize;
	Digests m_digestType;
	bool m_isDestroyed;
	Providers m_providerType;
	std::vector<byte> m_rndBuffer;
	Prngs m_rngGeneratorType;
	std::unique_ptr<IPrng> m_rngEngine;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SecureRandom(const SecureRandom&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SecureRandom& operator=(const SecureRandom&) = delete;

	/// <summary>
	/// Constructor: instantiate this class and initialize the rng.
	/// <para>Creates the pseudo-random seed generator and the base PRNG, and initializes the internal state.
	/// The default configuration is the Block cipher Counter Rng (BCR), using an AES-256 CTR cipher, seeded with the Auto Collection seed Provider (ACP)</para>
	/// </summary>
	/// 
	/// <param name="PrngType">The base random bytes generator (PRNG) used to power this wrapper; default is block cipher counter</param>
	/// <param name="ProviderType">The entropy provider type used to initialize the prng</param>
	/// <param name="DigestType">The message digest function used by the drbg as either the base PRF for that function (HCR or DCR), or to invoke the extended cipher configuration when using BCR</param>
	/// <param name="BufferSize">The byte size of the internal buffer; default is 4096</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the selected parameters are invalid</exception>
	explicit SecureRandom(Prngs PrngType = Prngs::BCR, Providers ProviderType = Providers::ACP, Digests DigestType = Digests::None, size_t BufferSize = 4096);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SecureRandom();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill an array of uint16 with pseudo-random
	/// </summary>
	///
	/// <param name="Output">The uint16 output array</param>
	/// <param name="Offset">The starting index within the Output array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Fill an array of uint32 with pseudo-random
	/// </summary>
	///
	/// <param name="Output">The uint32 output array</param>
	/// <param name="Offset">The starting index within the Output array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(std::vector<uint> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Fill an array of uint64 with pseudo-random
	/// </summary>
	///
	/// <param name="Output">The uint64 output array</param>
	/// <param name="Offset">The starting index within the Output array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Read Only: The random generators implementation name
	/// </summary>
	const std::string Name();

	//~~~Byte~~~//

	/// <summary>
	/// Return an array filled with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">Size of requested byte array</param>
	/// 
	/// <returns>Random byte array</returns>
	std::vector<byte> Generate(size_t Length);

	/// <summary>
	/// Fill the buffer with pseudo-random bytes using offsets
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Fill an array with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	void Generate(std::vector<byte> &Output);

	//~~~Char~~~//

	/// <summary>
	/// Get a random char
	/// </summary>
	/// 
	/// <returns>Random char</returns>
	char NextChar();

	/// <summary>
	/// Get a random unsigned char
	/// </summary>
	/// 
	/// <returns>Random unsigned char</returns>
	unsigned char NextUChar();

	//~~~Double~~~//

	/// <summary>
	/// Get a random double
	/// </summary>
	/// 
	/// <returns>Random double</returns>
	double NextDouble();

	//~~~Int16~~~//

	/// <summary>
	/// Get a random short integer
	/// </summary>
	/// 
	/// <returns>Random Int16</returns>
	short NextInt16();

	/// <summary>
	/// Get a random short integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <returns>Random Int16</returns>
	short NextInt16(short Maximum);

	/// <summary>
	/// Get a random short integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random Int16</returns>
	short NextInt16(short Maximum, short Minimum);


	//~~~UInt16~~~//

	/// <summary>
	/// Get a random 16bit ushort integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUInt16();

	/// <summary>
	/// Get a random 16bit ushort integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUInt16(ushort Maximum);

	/// <summary>
	/// Get a random 16bit ushort integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUInt16(ushort Maximum, ushort Minimum);

	//~~~Int32~~~//

	/// <summary>
	/// Get a random 32bit integer
	/// </summary>
	/// 
	/// <returns>Random Int32</returns>
	int NextInt32();

	/// <summary>
	/// Get a random 32bit integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int32</returns>
	int NextInt32(int Maximum);

	/// <summary>
	/// Get a random 32bit integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random Int32</returns>
	int NextInt32(int Maximum, int Minimum);

	//~~~UInt32~~~//

	/// <summary>
	/// Get a random 32bit unsigned integer
	/// </summary>
	/// 
	/// <returns>Random UInt32</returns>
	uint NextUInt32();

	/// <summary>
	/// Get a random 32bit unsigned integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	uint NextUInt32(uint Maximum);

	/// <summary>
	/// Get a random 32bit unsigned integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	uint NextUInt32(uint Maximum, uint Minimum);

	//~~~Int64~~~//

	/// <summary>
	/// Get a random 64bit long integer
	/// </summary>
	/// 
	/// <returns>Random Int64</returns>
	long NextInt64();

	/// <summary>
	/// Get a random 64bit long integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int64</returns>
	long NextInt64(long Maximum);

	/// <summary>
	/// Get a random 64bit long integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random Int64</returns>
	long NextInt64(long Maximum, long Minimum);

	//~~~UInt64~~~//

	/// <summary>
	/// Get a random 64bit unsigned integer
	/// </summary>
	/// 
	/// <returns>Random UInt64</returns>
	ulong NextUInt64();

	/// <summary>
	/// Get a random 64bit unsigned integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	ulong NextUInt64(ulong Maximum);

	/// <summary>
	/// Get a random 64bit unsigned integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	ulong NextUInt64(ulong Maximum, ulong Minimum);

	//~~~Reset~~~//

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	void Reset();
};

NAMESPACE_PRNGEND
#endif
