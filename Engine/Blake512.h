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
// An implementation of the Blake digest with a 512 bit digest size.
// Written by John Underhill, January 12, 2015
// contact: develop@vtdev.com

#ifndef _CEXENGINE_BLAKE512_H
#define _CEXENGINE_BLAKE512_H

#include "IDigest.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/// <summary>
/// Blake512: An implementation of the Blake digest with a 512 bit return size
/// </summary> 
/// 
/// <example>
/// <description>Example using the ComputeHash method:</description>
/// <code>
/// Blake512 digest;
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
/// <item><description>Digest size is 64 bytes, (512 bits).</description></item>
/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods</description>/></item>
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
class Blake512 : public IDigest
{
private:
	static constexpr unsigned int BLOCK_SIZE = 64;
	static constexpr unsigned int DIGEST_SIZE = 64;
	static constexpr unsigned int PAD_LENGTH = 111;
	static constexpr unsigned int ROUNDS = 16;
	static constexpr ulong TN_888 = 888;
	static constexpr ulong TN_1024 = 1024;

	unsigned int _dataLen = 0;
	std::vector<byte> _digestState;
	std::vector<ulong> _HashVal;
	bool _isDestroyed;
	bool _isNullT;
	std::vector<ulong> _M;
	std::vector<byte> _Padding;
	std::vector<ulong> _salt64;
	ulong _T;
	std::vector<ulong> _V;

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
	virtual CEX::Enumeration::Digests Enumeral() { return CEX::Enumeration::Digests::Blake512; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name() { return "Blake512"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the digest
	/// </summary>
	Blake512()
		:
		_digestState(128, 0),
		_HashVal(8, 0),
		_Padding(128, 0),
		_salt64(4, 0),
		_M(16, 0),
		_V(16, 0),
		_isDestroyed(false)
	{
		_Padding[0] = 0x80;
		Initialize();
	}

	/// <summary>
	/// Initialize the class with a salt value
	/// </summary>
	/// 
	/// <param name="Salt">The optional salt value; must be 4 unsigned longs in length</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the salt length is invalid</exception>
	Blake512(std::vector<ulong> Salt)
		:
		_HashVal(8, 0),
		_salt64(4, 0),
		_M(16, 0),
		_V(16, 0),
		_Padding(64, 0),
		_digestState(64, 0),
		_isDestroyed(false)
	{
		if (Salt.size() != 4)
			throw CryptoDigestException("Blake512:Ctor", "The Salt array length must be 4!");

		for (unsigned int i = 0; i < Salt.size(); i++)
			_salt64[i] = Salt[i];

		_Padding[0] = 0x80;
		Initialize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Blake512()
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
	void Reset();

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	void Update(byte Input);

private:
	void Compress64(const std::vector<byte> &pbBlock, unsigned int Offset);
	void G64(unsigned int A, unsigned int B, unsigned int C, unsigned int D, unsigned int R, unsigned int I);
	void G64BLK(unsigned int Index);
	void Initialize();
};

NAMESPACE_DIGESTEND
#endif
