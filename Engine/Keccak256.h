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
// An implementation of the SHA-3 digest based on Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. 
// SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.
// 
// Implementation Details:
// An implementation of the SHA-3 digest with a 256 bit return size. 
// Written by John Underhill, September 19, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_KECCAK256_H
#define _CEXENGINE_KECCAK256_H

#include "IDigest.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

/// <summary>
/// Keccak256: An implementation of the SHA-3 Keccak digest
/// </summary>
///
/// <example>
/// <description>Example using the ComputeHash method:</description>
/// <code>
/// Keccak256 digest;
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
/// <item><description>Hash sizes are 28, 32, and 36 bytes (224, 256, and 288 bits).</description></item>
/// <item><description>Block sizes are 144, 128, and 136 bytes (1152, 1024, 1088 bits).</description></item>
/// <item><description>Use the <see cref="BlockSize"/> property to determine block sizes at runtime.</description></item>
/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
/// 
/// <list type="number">
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.</description></item>
/// <item><description>SHA3 <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf">Keccak Slides</a>.</description></item>
/// <item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
/// </list>
/// </remarks>
class Keccak256 : public IDigest
{
private:
	unsigned int _blockSize;
	std::vector<byte> _buffer;
	unsigned int _bufferIndex;
	unsigned int _digestSize;
	bool _isDestroyed;
	std::vector<ulong> _state;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual unsigned int BlockSize() { return _blockSize; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual unsigned int DigestSize() { return _digestSize; }

	/// <summary>
	/// Get: The digests type enumeration member
	/// </summary>
	virtual CEX::Enumeration::Digests Enumeral() { return CEX::Enumeration::Digests::Keccak256; }

	/// <summary>
	/// Get: Digest name
	/// </summary>
	virtual const char *Name() { return "Keccak256"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the digest
	/// </summary>
	///
	/// <param name="DigestSize">Digest return size in bits</param>
	Keccak256(int DigestSize = 256)
		:
		_isDestroyed(false),
		_blockSize(0),
		_buffer(0),
		_bufferIndex(0),
		_digestSize(0),
		_state(25, 0)
	{
		// test for legal sizes; default at 256
		if (DigestSize == 224)
			_digestSize = 224 / 8;
		else if (DigestSize == 288)
			_digestSize = 288 / 8;
		else
			_digestSize = 256 / 8;

		_blockSize = 200 - (_digestSize * 2);

		Initialize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Keccak256()
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
	/// Update the digest with a single byte
	/// </summary>
	///
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input);

private:
	void Initialize();
};

NAMESPACE_DIGESTEND
#endif
