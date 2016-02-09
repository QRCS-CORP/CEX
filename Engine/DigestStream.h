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
// Written by John Underhill, January 21, 2015
// contact: develop@vtdev.com

#ifndef _CEXENGINE_DIGESTSTREAM_H
#define _CEXENGINE_DIGESTSTREAM_H

#include "Common.h"
#include "CryptoProcessingException.h"
#include "DigestFromName.h"
#include "Event.h"
#include "IByteStream.h"

NAMESPACE_PROCESSING

/// <summary>
/// Digest stream helper class.
/// <para>Wraps Message Digest stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of hashing a Stream:</description>
/// <code>
/// SHA512* eng = new SHA512();
/// StreamDigest dstrm(eng);
/// // get the hash code
/// hash = dstrm.ComputeHash(Input);
/// delete eng;
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Uses any of the implemented Digests using either the IDigest interface, or a Digests enumeration member.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either of the ComputeHash() calls.</description></item>
/// </list>
/// </remarks>
class DigestStream
{
private:
	static constexpr unsigned int BUFFER_SIZE = 64 * 1024;

	unsigned int _blockSize;
	CEX::Digest::IDigest* _digestEngine;
	bool _destroyEngine;
	CEX::IO::IByteStream* _inStream;
	bool _isDestroyed = false;
	long _progressInterval;

	DigestStream() { }

public:

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	CEX::Event::Event<int> ProgressPercent;

	/// <summary>
	/// Initialize the class with a digest instance
	/// <para>Digest must be fully initialized before calling this method.</para>
	/// </summary>
	/// 
	/// <param name="Digest">The initialized Digest instance</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a null Digest is used</exception>
	DigestStream(CEX::Digest::IDigest* Digest)
		:
		_blockSize(Digest->BlockSize()),
		_destroyEngine(false),
		_digestEngine(Digest),
		_isDestroyed(false),
		_progressInterval(0)
	{
		if (Digest == 0)
			throw CEX::Exception::CryptoProcessingException("DigestStream:CTor", "The Digest can not be null!");
	}

	/// <summary>
	/// Initialize the class with a digest enumeration
	/// </summary>
	/// 
	/// <param name="Digest">The digest enumeration member</param>
	DigestStream(CEX::Enumeration::Digests Digest)
		:
		_destroyEngine(true),
		_isDestroyed(false),
		_progressInterval(0)
	{
		_digestEngine = CEX::Helper::DigestFromName::GetInstance(Digest);
		_blockSize = _digestEngine->BlockSize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~DigestStream()
	{
		Destroy();
	}

	/// <summary>
	/// Process the entire length of the Input Stream
	/// </summary>
	/// 
	/// <returns>The Message Digest</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> ComputeHash(CEX::IO::IByteStream* InStream);

	/// <summary>
	/// Process a length within the Input stream using an Offset
	/// </summary>
	/// 
	/// <returns>The Message Digest</returns>
	/// <param name="Input">The Input array to process</param>
	/// <param name="InOffset">The Input array starting offset</param>
	/// <param name="Length">The number of bytes to process</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> ComputeHash(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length);

private:
	void CalculateInterval(unsigned int Length);
	void CalculateProgress(unsigned int Length, bool Completed = false);
	std::vector<byte> Compute(unsigned int Length);
	std::vector<byte> Compute(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length);
	void Destroy();
};

NAMESPACE_PROCESSINGEND
#endif
