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
// An implementation of the SHA3 digest finalist, Blake, designed by Jean-Philippe Aumasson, Luca Henzen, Willi Meier, and Raphael C.-W. Phan. 
// SHA3 Proposal <a href="https://131002.net/blake/blake.pdf">Blake</a>.
// 
// Implementation Details:
// An implementation of the Blake digest with a 256 bit digest size.
// Written by John Underhill, January 12, 2015
// contact: develop@vtdev.com

#ifndef _CEXENGINE_BLAKE256_H
#define _CEXENGINE_BLAKE256_H

#include "IDigest.h"

NAMESPACE_DIGEST

/// <summary>
/// Blake256: An implementation of the Blake digest with a 256 bit return size
/// </summary> 
/// 
/// <example>
/// <description>Example using the ComputeHash method:</description>
/// <code>
/// Blake256 digest;
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
/// <item><description>Block size is 32 bytes, (256 bits).</description></item>
/// <item><description>Digest size is 32 bytes, (256 bits).</description></item>
/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="https://131002.net/blake">SHA3 Proposal Blake</a>.</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3: Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
/// <item><description>SHA3 Submission in C: <a href="https://131002.net/blake/blake_ref.c">blake_ref.c</a>.</description></item>
/// </list>
/// </remarks>
class Blake256 : public IDigest
{
private:
	static constexpr size_t BLOCK_SIZE = 32;
	static constexpr size_t DIGEST_SIZE = 32;
	static constexpr size_t PAD_LENGTH = 55;
	static constexpr size_t ROUNDS = 14;
	static constexpr ulong TN_440 = 440;
	static constexpr ulong TN_512 = 512;

	size_t _dataLen = 0;
	bool _isDestroyed;
	std::vector<byte> _digestState;
	std::vector<uint> _HashVal;
	bool _isNullT;
	std::vector<uint> _M;
	std::vector<byte> _Padding;
	std::vector<uint> _salt32;
	ulong _T;
	std::vector<uint> _V;

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
	virtual CEX::Enumeration::Digests Enumeral() { return CEX::Enumeration::Digests::Blake256; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name() { return "Blake256"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the digest
	/// </summary>
	Blake256()
		:
		_isDestroyed(false),
		_digestState(64, 0),
		_HashVal(8, 0),
		_M(16, 0),
		_Padding(64, 0),
		_salt32(4, 0),
		_V(16, 0)
	{
		_Padding[0] = 0x80;
		Initialize();
	}

	/// <summary>
	/// Initialize the class with a salt value
	/// </summary>
	/// 
	/// <param name="Salt">The optional salt value; must be 4 unsigned ints in length</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the salt length is invalid</exception>
	explicit Blake256(std::vector<uint> Salt)
		:
		_isDestroyed(false),
		_digestState(64, 0),
		_HashVal(8, 0),
		_M(16, 0),
		_Padding(64, 0),
		_salt32(4, 0),
		_V(16, 0)
	{
		if (Salt.size() != 4)
			throw CryptoDigestException("Blake256:Ctor", "The Salt array length must be 4!");

		for (size_t i = 0; i < _salt32.size(); i++)
			_salt32[i] = Salt[i];

		_Padding[0] = 0x80;
		Initialize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Blake256()
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
	void Reset();

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	void Update(byte Input);

private:
	void G32(uint A, uint B, uint C, uint D, uint R, uint I);
	void G32BLK(uint Index);
	void Compress32(const std::vector<byte> &Block, size_t Offset);
	void Initialize();
};

NAMESPACE_DIGESTEND
#endif
