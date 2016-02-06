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
// An implementation of a keyed hash function wrapper; Hash based Message Authentication Code (HMAC).
// Written by John Underhill, September 24, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_HMAC_H
#define _CEXENGINE_HMAC_H

#include "IMac.h"
#include "IDigest.h"

NAMESPACE_MAC

/// <summary>
/// An implementation of a Hash based Message Authentication Code: HMAC.
/// <para>A HMAC as outlined in the NIST document: Fips 198-1</para>
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// CEX::Digest::SHA256* eng;
/// CEX::Mac::HMAC hmac1(eng);
/// hmac1.Initialize(key, [IV]);
/// hmac1.ComputeMac(Input, Output);
/// delete eng;
/// </code>
/// </example>
/// 
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
/// 
/// <seealso cref="CEX::Digest"/>
/// <seealso cref="CEX::Enumeration::Digests"/>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Key size should be equal to digest output size.</description></item>
/// <item><description>Block size is the Digests engines block size.</description></item>
/// <item><description>Digest size is the Digest engines digest return size.</description></item>
/// <item><description>The <see cref="ComputeMac(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>RFC 2104: <see href="http://tools.ietf.org/html/rfc2104">HMAC: Keyed-Hashing for Message Authentication</see>.</description></item>
/// <item><description>Fips 198-1: <see href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">The Keyed-Hash Message Authentication Code (HMAC)</see>.</description></item>
/// <item><description>Fips 180-4: <see href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Secure Hash Standard (SHS)</see>.</description></item>
/// <item><description>NMAC and HMAC Security: <see href="http://cseweb.ucsd.edu/~mihir/papers/hmac-new.pdf">NMAC and HMAC Security Proofs</see>.</description></item>
/// </list>
/// </remarks>
class HMAC : public IMac
{
protected:
	static constexpr byte IPAD = 0x36;
	static constexpr byte OPAD = 0x5C;

	unsigned int _blockSize;
	bool _isDestroyed;
	unsigned int _digestSize;
	bool _isInitialized;
	std::vector<byte> _inputPad;
	CEX::Digest::IDigest *_msgDigest;
	std::vector<byte> _outputPad;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual const unsigned int BlockSize() { return _msgDigest->BlockSize(); }

	/// <summary>
	/// Get: The macs type name
	/// </summary>
	virtual const CEX::Enumeration::Macs Enumeral() { return CEX::Enumeration::Macs::HMAC; }

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const unsigned int MacSize() { return _msgDigest->DigestSize(); }

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() { return _isInitialized; }

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() { return "HMAC"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the class
	/// </summary>
	/// 
	/// <param name="Digest">Message Digest instance</param>
	/// 
	/// <exception cref="CEX::Exception::CryptoMacException">Thrown if a null digest is used</exception>
	HMAC(CEX::Digest::IDigest *Digest)
		:
		_msgDigest(Digest),
		_blockSize(Digest->BlockSize()),
		_digestSize(Digest->DigestSize()),
		_inputPad(Digest->BlockSize(), 0),
		_outputPad(Digest->BlockSize(), 0),
		_isInitialized(false)
	{
		if (Digest == 0)
			throw CryptoMacException("HMAC:Ctor", "The digest has not been not initialized!");
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~HMAC()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Update the digest
	/// </summary>
	/// 
	/// <param name="Input">Hash input data</param>
	/// <param name="InOffset">Starting position with the Input array</param>
	/// <param name="Length">Length of data to process</param>
	virtual void BlockUpdate(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length);

	/// <summary>
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// 
	/// <returns>HMAC hash value</returns>
	virtual void ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Completes processing and returns the HMAC code
	/// </summary>
	/// 
	/// <param name="Output">Output array that receives the hash code</param>
	/// <param name="OutOffset">Offset within Output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	virtual unsigned int DoFinal(std::vector<byte> &Output, unsigned int OutOffset);

	/// <summary>
	/// Initialize the HMAC generator
	/// <para>Uses a Key and optional IV field to initialize the cipher.</para>
	/// </summary>
	/// 
	/// <param name="MacKey">A byte array containing the primary Key</param>
	/// <param name="IV">A byte array containing a secondary Initialization Vector</param>
	virtual void Initialize(const std::vector<byte> &MacKey, std::vector<byte> &IV = std::vector<byte>());

	/// <summary>
	/// Reset and initialize the underlying digest
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the digest with 1 byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input);

protected:
	inline void XOr(std::vector<byte> &A, byte N)
	{
		for (unsigned int i = 0; i < A.size(); ++i)
			A[i] ^= N;
	}
};

NAMESPACE_MACEND
#endif
