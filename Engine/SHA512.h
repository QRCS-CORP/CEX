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
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 512 bit return size. 
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SHA512_H
#define _CEXENGINE_SHA512_H

#include "IDigest.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/// <summary>
/// SHA512: An implementation of the SHA-2 digest with a 512 bit digest return size.
/// <para>The SHA-2 512 digest</para>
/// </summary> 
/// 
/// <example>
/// <description>Example using the ComputeHash method:</description>
/// <code>
/// SHA512 digest;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// digest.ComputeHash(Input, hash);
/// </code>
/// </example>
/// 
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
/// 
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Block size is 128 bytes, (1024 bits).</description></item>
/// <item><description>Digest size is 64 bytes, (512 bits).</description></item>
/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>SHA-2 <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</see>.</description></item>
/// </list>
/// </remarks>
class SHA512 : public IDigest
{
protected:
	static constexpr unsigned int BLOCK_SIZE = 128;
	static constexpr unsigned int DIGEST_SIZE = 64;

	ulong _btCounter1;
	ulong _btCounter2;
	unsigned int _bufferOffset;
	ulong _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7;
	bool _isDestroyed;
	std::vector<byte> _prcBuffer;
	std::vector<ulong> _wordBuffer;
	unsigned int _wordOffset;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual unsigned int BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual unsigned int DigestSize() { return DIGEST_SIZE; }

	/// <summary>
	/// Get: The digests type enumeration member
	/// </summary>
	virtual CEX::Enumeration::Digests Enumeral() { return CEX::Enumeration::Digests::SHA512; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name() { return "SHA512"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the digest
	/// </summary>
	SHA512()
		:
		_btCounter1(0),
		_btCounter2(0),
		_bufferOffset(0),
		_isDestroyed(false),
		_H0(0),
		_H1(0),
		_H2(0),
		_H3(0),
		_H4(0),
		_H5(0),
		_H6(0),
		_H7(0),
		_prcBuffer(8, 0),
		_wordBuffer(80, 0),
		_wordOffset(0)
	{
		Reset();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SHA512()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the input buffer is too short</exception>
	virtual void BlockUpdate(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length);

	/// <summary>
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The hash output value array</param>
	virtual void ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Do final processing and get the hash value
	/// </summary>
	/// 
	/// <param name="Output">The Hash output value array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <returns>Size of Hash value</returns>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too short</exception>
	virtual unsigned int DoFinal(std::vector<byte> &Output, const unsigned int OutOffset);

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input);

protected:
	void AdjustByteCounts();
	void Finish();
	void Initialize();
	void ProcessBlock();
	void ProcessLength(ulong LowWord, ulong HiWord);
	void ProcessWord(const std::vector<byte> &Input, unsigned int InOffset);

	inline static ulong Ch(ulong X, ulong Y, ulong Z)
	{
		return (X & Y) ^ (~X & Z);
	}

	inline  ulong Maj(ulong X, ulong Y, ulong Z)
	{
		return (X & Y) ^ (X & Z) ^ (Y & Z);
	}

	inline static ulong Sigma0(ulong X)
	{
		return ((X << 63) | (X >> 1)) ^ ((X << 56) | (X >> 8)) ^ (X >> 7);
	}

	inline static ulong Sigma1(ulong X)
	{
		return ((X << 45) | (X >> 19)) ^ ((X << 3) | (X >> 61)) ^ (X >> 6);
	}

	inline static ulong Sum0(ulong X)
	{
		return ((X << 36) | (X >> 28)) ^ ((X << 30) | (X >> 34)) ^ ((X << 25) | (X >> 39));
	}

	inline static ulong Sum1(ulong X)
	{
		return ((X << 50) | (X >> 14)) ^ ((X << 46) | (X >> 18)) ^ ((X << 23) | (X >> 41));
	}
};

NAMESPACE_DIGESTEND
#endif
