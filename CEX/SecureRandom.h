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
// along with this program.If not, see <http://www.gnu.org/licenses/>.
//
// 
// Implementation Details:
// An implementation of a Cryptographically Secure Pseudo Random Number Generator (SecureRandom). 
// Written by John Underhill, January 6, 2014
// Updated by December 1, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_SECURERANDOM_H
#define _CEX_SECURERANDOM_H

#include "IProvider.h"
#include "CryptoRandomException.h"

NAMESPACE_PRNG

using Provider::IProvider;
using Enumeration::Providers;
using Exception::CryptoRandomException;

/// <summary>
/// An implementation of a Cryptographically Secure Pseudo Random Number Generator: SecureRandom
/// 
/// <para>Uses a selectable entropy provider to generate random numbers.</para>
/// </summary>
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
	static const size_t BUFFER_SIZE = 4096;
	static const size_t MAXD16 = 16368;

	size_t m_bufferIndex;
	size_t m_bufferSize;
	std::vector<byte> m_byteBuffer;
	bool m_isDestroyed;
	IProvider* m_rngGenerator;
	Providers m_pvdType;

	SecureRandom(const SecureRandom&) = delete;
	SecureRandom& operator=(const SecureRandom&) = delete;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class.
	/// <para>Creates the selectable pseudo-random seed generator and initializes the internal state.</para>
	/// </summary>
	/// 
	/// <param name="ProviderType">The type of entropy provider to create; the default is the system crypto service provider (CSP)</param>
	/// <param name="BufferSize">Size of the internal buffer; must be at least 64 bytes</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if buffer size is too small</exception>
	explicit SecureRandom(Providers ProviderType = Providers::CSP, size_t BufferSize = 4096);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SecureRandom();

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	void Destroy();

	//~~~Byte~~~//

	/// <summary>
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Size">Size of requested byte array</param>
	/// 
	/// <returns>Random byte array</returns>
	std::vector<byte> GetBytes(size_t Size);

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	void GetBytes(std::vector<byte> &Output);

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
	/// Get a random non-negative short integer
	/// </summary>
	/// 
	/// <returns>Random Int16</returns>
	short NextInt16();

	/// <summary>
	/// Get a random non-negative short integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <returns>Random Int16</returns>
	short NextInt16(short Maximum);

	/// <summary>
	/// Get a random non-negative short integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int16</returns>
	short NextInt16(short Minimum, short Maximum);


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
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUInt16(ushort Minimum, ushort Maximum);

	//~~~Int32~~~//

	/// <summary>
	/// Get a random 32bit non-negative integer
	/// </summary>
	/// 
	/// <returns>Random Int32</returns>
	int Next();

	/// <summary>
	/// Get a random 32bit non-negative integer
	/// </summary>
	/// 
	/// <returns>Random Int32</returns>
	int NextInt32();

	/// <summary>
	/// Get a random 32bit non-negative integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int32</returns>
	int NextInt32(int Maximum);

	/// <summary>
	/// Get a random 32bit non-negative integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int32</returns>
	int NextInt32(int Minimum, int Maximum);

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
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	uint NextUInt32(uint Minimum, uint Maximum);

	//~~~Int64~~~//

	/// <summary>
	/// Get a random 64bit long integer
	/// </summary>
	/// 
	/// <returns>Random Int64</returns>
	long NextLong();

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
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random Int64</returns>
	long NextInt64(long Minimum, long Maximum);

	//~~~UInt64~~~//

	/// <summary>
	/// Get a random 64bit ulong integer
	/// </summary>
	/// 
	/// <returns>Random UInt64</returns>
	ulong NextUInt64();

	/// <summary>
	/// Get a random 64bit ulong integer up to a maximum value
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	ulong NextUInt64(ulong Maximum);

	/// <summary>
	/// Get a random 64bit ulong integer ranged between minimum and maximum sizes
	/// </summary>
	/// 
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	ulong NextUInt64(ulong Minimum, ulong Maximum);

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	void Reset();

private:
	std::vector<byte> GetByteRange(ulong Maximum);
	std::vector<byte> GetBits(std::vector<byte> &Data, ulong Maximum);
};

NAMESPACE_PRNGEND
#endif