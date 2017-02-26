// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Implementation Details:</description>
// An implementation of an ISAAC pseudo-random number generator (ISAAC)
// Updated September 30, 2016
// Written by John Underhill, January 09, 2014

#ifndef _CEXENGINE_ISAAC_H
#define _CEXENGINE_ISAAC_H

#include "IDrbg.h"

NAMESPACE_DRBG

/// <summary>
/// An implementation of an ISAAC pseudo-random number generator (ISAAC)
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// ISAAC gen(Seed);
/// gen.GetSeed(Output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>ISAAC a fast cryptographic <a href="http://www.burtleburtle.net/bob/rand/isaacafa.html">Random Number Generator</a>.</description></item>
/// <item><description>Rossettacode <a href="http://rosettacode.org/wiki/The_ISAAC_Cipher">Example implementations</a>.</description></item>
/// </list>
/// </remarks>
class ISAAC : public IDrbg
{
private:
	static constexpr uint GOLDEN_RATIO = 0x9e3779b9;
	static constexpr uint UINT_SIZE = 4;
	static constexpr uint ULNG_SIZE = 8;
	static constexpr size_t MAXKEY_SIZE = 256 * UINT_SIZE;
	static constexpr size_t MINKEY_SIZE = 32;
	static constexpr size_t STATE_SIZE = 1 << ULNG_SIZE;
	static constexpr uint SHIFT_MASK = (STATE_SIZE - 1) << 2;

	size_t m_accululator;
	size_t m_cycCounter;
	bool m_isDestroyed;
	bool m_isInitialized;
	uint m_lstResult;
	size_t m_rndCount;
	std::vector<uint> m_rndResult;
	size_t m_rslCounter;
	std::vector<uint> m_wrkBuffer;

	ISAAC(const ISAAC&) = delete;
	ISAAC& operator=(const ISAAC&) = delete;

public:
	//~~~Properties~~~//

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const Enumeration::Drbgs Enumeral() { return Enumeration::Drbgs::ISAAC; }

	/// <summary>
	/// Get: Generator is ready to produce random
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Minimum initialization key size in bytes.
	/// <para>Combined sizes of key, salt, and info must be at least this size.</para></para>
	/// </summary>
	virtual size_t MinSeedSize() { return MINKEY_SIZE; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "ISAAC"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class using a seed value
	/// </summary>
	///
	/// <param name="Seed">The initial state values; must be between 2 and 256, 32bit values</param>
	///
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if an invalid seed size is used</exception>
	explicit ISAAC()
		:
		m_accululator(0),
		m_cycCounter(0),
		m_isDestroyed(false),
		m_isInitialized(false),
		m_lstResult(0),
		m_rndCount(0),
		m_rndResult(STATE_SIZE),
		m_rslCounter(0),
		m_wrkBuffer(STATE_SIZE)
	{
	}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~ISAAC()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Generate a block of pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output);

	/// <summary>
	/// Generate pseudo random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length);

	/// <summary>
	/// Initialize the generator with a RngParams structure containing the key, and optional nonce, and info string.
	/// </summary>
	/// 
	/// <param name="GenParam">The RngParams containing the generators keying material</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the key is not a legal size</exception>
	virtual void Initialize(const RngParams &GenParam);

	/// <summary>
	/// Initialize the generator with a key.
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the key is not a legal size</exception>
	virtual void Initialize(const std::vector<byte> &Key);

	/// <summary>
	/// Initialize the generator with key and nonce arrays
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Nonce">The nonce value containing an additional source of entropy</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the key is not a legal size</exception>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Nonce);

	/// <summary>
	/// Initialize the generator with a key, a nonce array, and an information string or nonce
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Nonce">The nonce value used as an additional source of entropy</param>
	/// <param name="Info">The information string or nonce used as a third source of entropy</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the key is not a legal size</exception>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Nonce, const std::vector<byte> &Info);

	/// <summary>
	/// Reset the generator
	/// </summary>
	void Reset();

	/// <summary>
	/// Update the generators Nonce value.
	/// <para>If the seed array size is equal to a legal key size, the key and counter are replaced with the new values.
	/// If the seed array size is equal to the counter value (16 bytes), the counter is replaced.</para>
	/// </summary>
	/// 
	/// <param name="Seed">The new seed value array</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the seed is too small</exception>
	virtual void Update(const std::vector<byte> &Seed);

private:
	uint Generate();
	void Mix(uint &A, uint &B, uint &C, uint &D, uint &E, uint &F, uint &G, uint &H);
	void Process(bool MixState);
	void Transform();
};

NAMESPACE_DRBGEND
#endif
