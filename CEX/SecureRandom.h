
// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
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
//
// Updated by September 24, 2019
// Contact: develop@qscs.ca

#ifndef CEX_SECURERANDOM_H
#define CEX_SECURERANDOM_H

#include "IProvider.h"
#include "CryptoRandomException.h"
#include "IPrng.h"
#include "SecureVector.h"

NAMESPACE_PRNG

using Exception::CryptoRandomException;
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
/// The PRNG and random provider type names are loaded through the constructor, instantiating internal instances 
/// of those classes and auto-initializing the base PRNG. \n
/// The default configuration uses the wide-block Rijndael-256 in extended mode, with a CTR mode generator and a 256-bit key (BCR), 
/// and the auto seed collection provider. \n
/// The secure random class can use any combination of the base PRNGs and random providers.</para>
/// </remarks>
/// 
/// <example>
/// <c>
/// SecureRandom rnd;
/// int32_t x = rnd.NextInt32();
/// </c>
/// </example>
class SecureRandom
{
private:

	static const size_t BUFFER_SIZE = 1024;
	class ScrState;

	std::unique_ptr<ScrState> m_scrState;
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
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the selected parameters are invalid</exception>
	explicit SecureRandom(Prngs PrngType = Prngs::BCR, Providers ProviderType = Providers::ACP);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SecureRandom();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector of uint16 with pseudo-random using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The uint16 destination array</param>
	/// <param name="Offset">The starting index within the destination array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(std::vector<uint16_t> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Fill a secure-vector of uint16 with pseudo-random using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The uint16 destination array</param>
	/// <param name="Offset">The starting index within the destination array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(SecureVector<uint16_t> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Fill a standard-vector of uint32 with pseudo-random using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The uint32 destination array</param>
	/// <param name="Offset">The starting index within the destination array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(std::vector<uint32_t> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Fill a secure-vector of uint32 with pseudo-random using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The uint32 destination array</param>
	/// <param name="Offset">The starting index within the destination array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(SecureVector<uint32_t> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Fill a standard-vector of uint64 with pseudo-random using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The uint64 destination array</param>
	/// <param name="Offset">The starting index within the destination array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(std::vector<uint64_t> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Fill a secure-vector of uint64 with pseudo-random using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The uint64 destination array</param>
	/// <param name="Offset">The starting index within the destination array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	void Fill(SecureVector<uint64_t> &Output, size_t Offset, size_t Elements);

	/// <summary>
	/// Read Only: The random generators implementation name
	/// </summary>
	const std::string Name();

	//~~~Byte~~~//

	/// <summary>
	/// Return an array filled with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">Size of requested uint8_t array</param>
	/// 
	/// <returns>Random uint8_t array</returns>
	std::vector<uint8_t> Generate(size_t Length);

	/// <summary>
	/// Fill a standard uint8_t vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to write to the destination array</param>
	void Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Fill a secure uint8_t vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination secure-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to write to the destination array</param>
	void Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination vector to fill</param>
	void Generate(std::vector<uint8_t> &Output);

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination secure-vector to fill</param>
	void Generate(SecureVector<uint8_t> &Output);

	//~~~Char~~~//

	/// <summary>
	/// Get a random char
	/// </summary>
	/// 
	/// <returns>Random char</returns>
	char NextChar();

	/// <summary>
	/// Get a random uint8_t
	/// </summary>
	/// 
	/// <returns>Random uint8_t</returns>
	uint8_t NextUChar();

	//~~~Double~~~//

	/// <summary>
	/// Get a random double
	/// </summary>
	/// 
	/// <returns>Random double</returns>
	double NextDouble();

	//~~~Int16~~~//

	/// <summary>
	/// Get a random int16_t integer
	/// </summary>
	/// 
	/// <returns>Random Int16</returns>
	int16_t NextInt16();

	/// <summary>
	/// Get a random int16_t integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <returns>Random Int16</returns>
	int16_t NextInt16(int16_t Maximum);

	/// <summary>
	/// Get a random int16_t integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random Int16</returns>
	int16_t NextInt16(int16_t Maximum, int16_t Minimum);


	//~~~UInt16~~~//

	/// <summary>
	/// Get a random 16bit uint16_t integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	uint16_t NextUInt16();

	/// <summary>
	/// Get a random 16bit uint16_t integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	uint16_t NextUInt16(uint16_t Maximum);

	/// <summary>
	/// Get a random 16bit uint16_t integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	uint16_t NextUInt16(uint16_t Maximum, uint16_t Minimum);

	//~~~Int32~~~//

	/// <summary>
	/// Get a random 32bit integer
	/// </summary>
	/// 
	/// <returns>Random Int32</returns>
	int32_t NextInt32();

	/// <summary>
	/// Get a random 32bit integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int32</returns>
	int32_t NextInt32(int32_t Maximum);

	/// <summary>
	/// Get a random 32bit integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random Int32</returns>
	int32_t NextInt32(int32_t Maximum, int32_t Minimum);

	//~~~UInt32~~~//

	/// <summary>
	/// Get a random 32bit unsigned integer
	/// </summary>
	/// 
	/// <returns>Random UInt32</returns>
	uint32_t NextUInt32();

	/// <summary>
	/// Get a random 32bit unsigned integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	uint32_t NextUInt32(uint32_t Maximum);

	/// <summary>
	/// Get a random 32bit unsigned integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	uint32_t NextUInt32(uint32_t Maximum, uint32_t Minimum);

	//~~~Int64~~~//

	/// <summary>
	/// Get a random 64bit int64_t integer
	/// </summary>
	/// 
	/// <returns>Random Int64</returns>
	int64_t NextInt64();

	/// <summary>
	/// Get a random 64bit int64_t integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int64</returns>
	int64_t NextInt64(int64_t Maximum);

	/// <summary>
	/// Get a random 64bit int64_t integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random Int64</returns>
	int64_t NextInt64(int64_t Maximum, int64_t Minimum);

	//~~~UInt64~~~//

	/// <summary>
	/// Get a random 64bit unsigned integer
	/// </summary>
	/// 
	/// <returns>Random UInt64</returns>
	uint64_t NextUInt64();

	/// <summary>
	/// Get a random 64bit unsigned integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	uint64_t NextUInt64(uint64_t Maximum);

	/// <summary>
	/// Get a random 64bit unsigned integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	uint64_t NextUInt64(uint64_t Maximum, uint64_t Minimum);
};

NAMESPACE_PRNGEND
#endif
