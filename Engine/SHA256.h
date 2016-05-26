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
// An implementation of the SHA-2 digest with a 256 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 256 bit return size. 
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SHA256_H
#define _CEXENGINE_SHA256_H

#include "IDigest.h"
#include "IntUtils.h"

NAMESPACE_DIGEST
    
/// <summary>
/// SHA256: An implementation of the SHA-2 digest with a 256 bit digest return size
/// </summary> 
/// 
/// <example>
/// <description>Example using the ComputeHash method:</description>
/// <code>
/// SHA256 digest;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// digest.ComputeHash(Input, hash);
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Digest::IDigest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Block size is 64 bytes, (512 bits).</description></item>
/// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Specification</a>.</description></item>
/// </list>
/// </remarks>
class SHA256 : public IDigest
{
private:
	static constexpr size_t BLOCK_SIZE = 64;
	static constexpr size_t DIGEST_SIZE = 32;

	size_t _bufferOffset;
	size_t _byteCount;
	bool _isDestroyed;
	uint _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7;
	std::vector<byte> _prcBuffer;
	std::vector<uint> _wordBuffer;
	size_t _wordOffset = 0;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual size_t DigestSize() { return DIGEST_SIZE; }

	/// <summary>
	/// Get: The digests type enumeration member
	/// </summary>
	virtual CEX::Enumeration::Digests Enumeral() { return CEX::Enumeration::Digests::SHA256; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name() { return "SHA256"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the digest
	/// </summary>
	SHA256()
		:
		_bufferOffset(0),
		_byteCount(0),
		_prcBuffer(4, 0),
		_wordBuffer(64, 0),
		_wordOffset(0),
		_isDestroyed(false)
	{
		Initialize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SHA256()
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
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

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
	virtual size_t DoFinal(std::vector<byte> &Output, const size_t OutOffset);

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

private:
	void Finish();
	void Initialize();
	void ProcessBlock();
	void ProcessLength(ulong BitLength);
	void ProcessWord(const std::vector<byte> &Input, size_t Offset);

	inline static uint Sum1Ch(uint X, uint Y, uint Z)
	{
		return (((X >> 6) | (X << 26)) ^ ((X >> 11) | (X << 21)) ^ ((X >> 25) | (X << 7))) + ((X & Y) ^ ((~X) & Z));
	}

	inline static uint Sum0Maj(uint X, uint Y, uint Z)
	{
		return (((X >> 2) | (X << 30)) ^ ((X >> 13) | (X << 19)) ^ ((X >> 22) | (X << 10))) + ((X & Y) ^ (X & Z) ^ (Y & Z));
	}

	inline static uint Theta0(uint X)
	{
		return ((X >> 7) | (X << 25)) ^ ((X >> 18) | (X << 14)) ^ (X >> 3);
	}

	inline static uint Theta1(uint X)
	{
		return ((X >> 17) | (X << 15)) ^ ((X >> 19) | (X << 13)) ^ (X >> 10);
	}
};

NAMESPACE_DIGESTEND
#endif
