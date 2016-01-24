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
// Implementation Details:
// An implementation of a Cryptographically Secure Pseudo Random Number Generator (SecureRandom). 
// Uses the <see href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</see> class to produce pseudo random output.
// Written by John Underhill, January 6, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SECURERANDOM_H
#define _CEXENGINE_SECURERANDOM_H

#include "CSPRsg.h"
#include "IntUtils.h"
#include "BitConverter.h"
#include "CryptoRandomException.h"

NAMESPACE_PRNG

using CEX::Exception::CryptoRandomException;

/// <summary>
/// An implementation of a Cryptographically Secure Pseudo Random Number Generator: SecureRandom. 
/// 
/// <para>Uses the default crypto random provider to generate random numbers.</para>
/// </summary>
/// 
/// <example>
/// <c>
/// SecureRandom rnd;
/// int x = rnd.NextInt32();
/// </c>
/// </example>
/// 
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
class SecureRandom
{
protected:
	static constexpr unsigned int BUFFER_SIZE = 4096;
	static constexpr unsigned int MAXD16 = 16368;

	bool _isDestroyed;
	CEX::Seed::CSPRsg* _rngGenerator;
	std::vector<byte> _byteBuffer;
	unsigned int _bufferIndex;
	unsigned int _bufferSize;

public:

	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	/// 
	/// <param name="BufferSize">Size of the internal buffer; must be at least 64 bytes</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if buffer size is too small</exception>
	SecureRandom(unsigned int BufferSize = BUFFER_SIZE)
		:
		_bufferIndex(0),
		_bufferSize(BufferSize),
		_byteBuffer(BufferSize),
		_isDestroyed(false)
	{
		if (BufferSize < 64)
			throw CryptoRandomException("SecureRandom:Ctor", "Buffer size must be at least 64 bytes!");

		Reset();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SecureRandom()
	{
		Destroy();
	}


	void Destroy();
	std::vector<byte> GetBytes(unsigned int Size);
	void GetBytes(std::vector<byte> &Output);
	char NextChar();
	unsigned char NextUChar();
	double NextDouble();
	short NextInt16();
	short NextInt16(short Maximum);
	short NextInt16(short Minimum, short Maximum);
	unsigned short NextUInt16();
	unsigned short NextUInt16(unsigned short Maximum);
	unsigned short NextUInt16(unsigned short Minimum, unsigned short Maximum);
	int Next();
	int NextInt32();
	int NextInt32(int Maximum);
	int NextInt32(int Minimum, int Maximum);
	unsigned int NextUInt32();
	unsigned int NextUInt32(unsigned int Maximum);
	unsigned int NextUInt32(unsigned int Minimum, unsigned int Maximum);
	long NextLong();
	long NextInt64();
	long NextInt64(long Maximum);
	long NextInt64(long Minimum, long Maximum);
	ulong NextUInt64();
	ulong NextUInt64(ulong Maximum);
	ulong NextUInt64(ulong Minimum, ulong Maximum);
	void Reset();

protected:
	std::vector<byte> GetByteRange(ulong Maximum);
	std::vector<byte> GetBits(std::vector<byte> Data, ulong Maximum);
};

NAMESPACE_PRNGEND
#endif