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
// An implementation of an XorShift+ Generator (XSG)
// Updated September 30, 2016
// Written by John Underhill, January 09, 2014

#ifndef _CEXENGINE_XSG_H
#define _CEXENGINE_XSG_H

#include "IDrbg.h"

NAMESPACE_DRBG

/// <summary>
/// An implementation of an XorShift+ Generator (XSG).
/// <para>This generator is not generally considered a cryptographic quality generator. 
/// This generator is suitable as a quality high-speed number generator, but not to be used directly for tasks that require secrecy, ex. key generation.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// XSG gen(Seed);
/// gen.GetSeed(Output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Further scramblings of Marsaglia’s <a href="http://vigna.di.unimi.it/ftp/papers/xorshiftplus.pdf">Xorshift Generators</a>.</description></item>
/// <item><description><a href="http://xorshift.di.unimi.it/">Xorshift+ generators</a> and the PRNG shootout.</description></item>
/// </list>
/// </remarks>
class XSG : public IDrbg
{
private:
	static constexpr int SIZE32 = 4;
	static constexpr int SIZE64 = 8;
	static constexpr int MAXSEED = 16;
	static constexpr size_t MINKEY_SIZE = 32;
	static constexpr ulong Z1 = 0x9E3779B97F4A7C15;
	static constexpr ulong Z2 = 0xBF58476D1CE4E5B9;
	static constexpr ulong Z3 = 0x94D049BB133111EB;
	static constexpr ulong Z4 = 1181783497276652981;

	bool m_isDestroyed;
	bool m_isInitialized;
	bool m_isShift1024;
	size_t m_stateOffset;
	std::vector<ulong> m_stateSeed;
	std::vector<ulong> m_wrkBuffer;
	std::vector<ulong> JMP128;
	std::vector<ulong> JMP1024;

	XSG() = delete;
	XSG(const XSG&) = delete;
	XSG& operator=(const XSG&) = delete;

public:
	//~~~Properties~~~//

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const Enumeration::Drbgs Enumeral() { return Enumeration::Drbgs::XSG; }

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
	virtual const char *Name() { return "XSG"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class with a random seed array.
	/// <para>Initializing with 2 ulongs invokes the 128 bit function, initializing with 16 ulongs
	/// invokes the 1024 bit function.</para>
	/// </summary>
	///
	/// <param name="Seed">The initial state values; can be either 2, or 16, 64bit values</param>
	///
	/// <exception cref="CEX::Exception::CryptoGeneratorException">Thrown if an invalid seed size is used</exception>
	explicit XSG(const std::vector<ulong> &Seed)
		:
		m_isDestroyed(false),
		m_isInitialized(false),
		m_isShift1024(false),
		m_stateOffset(0),
		m_stateSeed(Seed.size()),
		m_wrkBuffer(Seed.size())
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Seed.size() != 2 && Seed.size() != 16)
			throw CryptoGeneratorException("XSG:CTor", "The seed array length must be either 2 or 16 long values!");

		for (size_t i = 0; i < Seed.size(); ++i)
		{
			if (Seed[i] == 0)
				throw CryptoGeneratorException("XSG:CTor", "Seed values can not be zero!");
		}
#endif
		size_t len = Seed.size() * sizeof(ulong);
		memcpy(&m_stateSeed[0], &Seed[0], len);
		m_isShift1024 = (Seed.size() == 16);

		if (!m_isShift1024)
			JMP128 = { 0x8a5cd789635d2dffULL, 0x121fd2155c472f96ULL };
		else
			JMP1024 = { 
				0x84242f96eca9c41dULL, 0xa3c65b8776f96855ULL, 0x5b34a39f070b5837ULL, 0x4489affce4f31a1eULL,
				0x2ffeeb0a48316f40ULL, 0xdc2d9891fe68c022ULL, 0x3659132bb12fea70ULL, 0xaac17d8efa43cab8ULL,
				0xc4cb815590989b13ULL, 0x5ee975283d71c93bULL, 0x691548c86c1bd540ULL, 0x7910c41d10a1e6a5ULL,
				0x0b5fc64563b3e2a8ULL, 0x047f7684e9fc949dULL, 0xb99181f2d8f685caULL, 0x284600e3f30e38c3ULL
			};

		Reset();
	}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~XSG()
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
	/// Increment the state by 64 blocks; used with the 128 and 1024 implementations
	/// </summary>
	void Jump();

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Implementation of java's Splittable function
	/// </summary>
	/// 
	/// <param name="X">Input integer</param>
	/// 
	/// <returns>A processed long integer</returns>
	ulong Split(ulong X);

private:

	int Next();

	void Jump128();
	void Jump1024();
	void GetSeed(size_t Size);
	ulong Shift128();
	ulong Shift1024();
};

NAMESPACE_DRBGEND
#endif
