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

#ifndef _CEXENGINE_MACSTREAM_H
#define _CEXENGINE_MACSTREAM_H

#include "Common.h"
#include "CryptoProcessingException.h"
#include "Event.h"
#include "IByteStream.h"
#include "IMac.h"

NAMESPACE_PROCESSING

/// <summary>
/// MAC stream helper class.
/// <para>Wraps Message Authentication Code (MAC) stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of hashing a Stream:</description>
/// <code>
/// SHA256* eng = new SHA256();
/// HMAC* mac = new HMAC(eng);
/// hmac->Initialize(Key, Iv);
/// MacStream ds(mac);
/// IByteStream* ms = new MemoryStream(Input);
/// Code = ds.ComputeMac(ms);
/// delete eng;
/// delete mac;
/// delete ms;
/// </code>
/// </example>
/// 
/// <seealso cref="CEX::Enumeration::Macs"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Uses any of the implemented <see cref="CEX::Enumeration::Macs">Macs</see> using the IMac interface.</description></item>
/// <item><description>Mac must be fully initialized before passed to the constructor.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either ComputeMac() calls.</description></item>
/// </list>
/// </remarks>
class MacStream
{
private:
	static constexpr unsigned int BUFFER_SIZE = 64 * 1024;

	unsigned int _blockSize;
	bool _destroyEngine;
	CEX::IO::IByteStream* _inStream;
	bool _isDestroyed = false;
	CEX::Mac::IMac* _macEngine;
	long _progressInterval;

	MacStream() { }

public:

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	CEX::Event::Event<int> ProgressPercent;

	/// <summary>
	/// Initialize the class with an initialized Mac instance
	/// </summary>
	/// 
	/// <param name="Mac">The initialized <see cref="CEX::Mac::IMac"/> instance</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if a null or uninitialized Mac is used</exception>
	MacStream(CEX::Mac::IMac* Mac)
		:
		_blockSize(Mac->BlockSize()),
		_destroyEngine(false),
		_isDestroyed(false),
		_macEngine(Mac),
		_progressInterval(0)
	{
		if (Mac == 0)
			throw CEX::Exception::CryptoProcessingException("MacStream:CTor", "The Mac can not be null!");
		if (!Mac->IsInitialized())
			throw CEX::Exception::CryptoProcessingException("MacStream:CTor", "The Mac is not initialized!");
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~MacStream()
	{
		Destroy();
	}

	/// <summary>
	/// Process the entire length of the Input Stream
	/// </summary>
	/// 
	/// <returns>The Mac Code</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> ComputeMac(CEX::IO::IByteStream* InStream);

	/// <summary>
	/// Process a length within the Input stream using an Offset
	/// </summary>
	/// 
	/// <returns>The Mac Code</returns>
	/// <param name="Input">The Input array to process</param>
	/// <param name="InOffset">The Input array starting offset</param>
	/// <param name="Length">The number of bytes to process</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> ComputeMac(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length);

private:
	void CalculateInterval(unsigned int Length);
	void CalculateProgress(unsigned int Length, bool Completed = false);
	std::vector<byte> Compute(unsigned int Length);
	std::vector<byte> Compute(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length);
	void Destroy();
};

NAMESPACE_PROCESSINGEND
#endif
