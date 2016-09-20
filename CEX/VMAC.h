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
// An implementation of a Variably Modified Permutation Composition based Message Authentication Code (VMPC-MAC).
// Written by John Underhill, January 11, 2014
// contact: develop@vtdev.com

#ifndef _CEXENGINE_VMAC_H
#define _CEXENGINE_VMAC_H

#include "IMac.h"

NAMESPACE_MAC

/// <summary>
/// An implementation of a Variably Modified Permutation Composition based Message Authentication Code
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// CEX::Mac::VMAC mac;
/// // initialize
/// mac.Initialize(Key, Iv);
/// // get mac code
/// mac.ComputeMac(Input, Output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>No fixed block size is used.</description></item>
/// <item><description>MAC return size is 20 bytes.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>VMPC <a href="http://www.vmpcfunction.com/vmpc_mac.pdf">MAC Specification</a>:  VMPC-MAC: A Stream Cipher Based Authenticated Encryption Scheme.</description></item>
/// <item><description>VMPC <a href="http://www.vmpcfunction.com/vmpcmac.htm">VMPC-MAC</a> Authenticated Encryption Scheme.</description></item>
/// <item><description>IETF <a href="http://www.okna.wroc.pl/vmpc.pdf">VMPC One-Way Function</a> and Stream Cipher.</description></item>
/// </list>
/// </remarks>
class VMAC : public IMac
{
private:
	static constexpr size_t BLOCK_SIZE = 256;
	static constexpr size_t MAC_SIZE = 20;
	static constexpr byte CT1F = (byte)0x1F;
	static constexpr byte CTFF = (byte)0xFF;

	size_t m_blockSize;
	bool m_isDestroyed;
	bool m_isInitialized;
	byte G;
	byte N;
	std::vector<byte> P;
	byte S;
	std::vector<byte> T;
	std::vector<byte> m_workingKey;
	std::vector<byte> m_workingIV;
	byte X1;
	byte X2;
	byte X3;
	byte X4;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual const size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: The macs type name
	/// </summary>
	virtual const Macs Enumeral() { return Macs::VMAC; }

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const size_t MacSize() { return MAC_SIZE; }

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() { return m_isInitialized; }

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() { return "VMAC"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the VMAC class
	/// </summary>
	VMAC()
		:
		m_blockSize(BLOCK_SIZE),
		m_isDestroyed(false),
		m_isInitialized(false),
		G(0),
		N(0),
		P(256),
		S(0),
		T(32),
		m_workingKey(0),
		m_workingIV(0),
		X1(0),
		X2(0),
		X3(0),
		X4(0)
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~VMAC()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">Offset within Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Get the Mac hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The output message code</param>
	virtual void ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Process the last block of data
	/// </summary>
	/// 
	/// <param name="Output">The hash value return</param>
	/// <param name="OutOffset">The offset in the data</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if Output array is too small</exception>
	virtual size_t DoFinal(std::vector<byte> &Output, size_t OutOffset);

	/// <summary>
	/// Initialize the VMPC MAC.
	/// <para>Uses the Key and IV fields of the KeyParams class.</para>
	/// </summary>
	/// 
	/// <param name="MacKey">A byte array containing the Key</param>
	/// <param name="IV">A byte array containing the Initialization Vector</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if a null or invalid Key, or IV is used</exception>
	virtual void Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV);

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
	/// <remarks>
	/// Section 3.2, table 2 <a href="http://vmpcfunction.com/vmpc_mac.pdf">VMPC-MAC: 
	/// A Stream Cipher Based Authenticated Encryption Scheme</a>
	/// </remarks>
	void InitKey(std::vector<byte> &KeyBytes, std::vector<byte> &IvBytes);
};

NAMESPACE_MACEND
#endif