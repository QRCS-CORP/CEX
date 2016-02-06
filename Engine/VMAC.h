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
/// An implementation of a Variably Modified Permutation Composition based Message Authentication Code: VMPC-MAC.
/// <para>A VMPC message code generator as outlined in the VMPC-MAC Specification</para>
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
/// <revisionHistory>
/// <revision date="2015/11/20" version="1.0.0.0">Initial C++ Library implemention</revision>
/// </revisionHistory>
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
/// <item><description>VMPC-MAC Specification: <see href="http://www.vmpcfunction.com/vmpc_mac.pdf"/> VMPC-MAC: A Stream Cipher Based Authenticated Encryption Scheme.</description></item>
/// <item><description>VMPC Paper: <see href="http://www.vmpcfunction.com/vmpcmac.htm"/> VMPC-MAC Authenticated Encryption Scheme.</description></item>
/// <item><description>IETF: <see href="http://www.okna.wroc.pl/vmpc.pdf"/> VMPC One-Way Function and Stream Cipher.</description></item>
/// </list>
/// </remarks>
class VMAC : public IMac
{
protected:
	static constexpr unsigned int BLOCK_SIZE = 256;
	static constexpr unsigned int MAC_SIZE = 20;
	static constexpr byte CT1F = (byte)0x1F;
	static constexpr byte CTFF = (byte)0xFF;

	unsigned int _blockSize;
	bool _isDestroyed;
	bool _isInitialized;
	byte _G;
	byte _N;
	std::vector<byte> _P;
	byte _S;
	std::vector<byte> _T;
	std::vector<byte> _workingKey;
	std::vector<byte> _workingIV;
	byte _X1;
	byte _X2;
	byte _X3;
	byte _X4;

public:

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual const unsigned int BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: The macs type name
	/// </summary>
	virtual const CEX::Enumeration::Macs Enumeral() { return CEX::Enumeration::Macs::VMAC; }

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const unsigned int MacSize() { return MAC_SIZE; }

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() { return _isInitialized; }

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() { return "VMAC"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize the VMAC class
	/// </summary>
	VMAC()
		:
		_blockSize(BLOCK_SIZE),
		_isDestroyed(false),
		_isInitialized(false),
		_G(0),
		_N(0),
		_P(256),
		_S(0),
		_T(32),
		_workingKey(0),
		_workingIV(0),
		_X1(0),
		_X2(0),
		_X3(0),
		_X4(0)
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~VMAC()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">Offset within Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid Input size is chosen</exception>
	virtual void BlockUpdate(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length);

	/// <summary>
	/// Get the Mac hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// 
	/// <returns>Mac Hash value</returns>
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
	virtual unsigned int DoFinal(std::vector<byte> &Output, unsigned int OutOffset);

	/// <summary>
	/// Initialize the VMPC MAC.
	/// <para>Uses the Key and IV fields of the KeyParams class.</para>
	/// </summary>
	/// 
	/// <param name="MacKey">A byte array containing the Key</param>
	/// <param name="IV">A byte array containing the Initialization Vector</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if a null or invalid Key, or IV is used</exception>
	virtual void Initialize(const std::vector<byte> &MacKey, std::vector<byte> &IV);

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

protected:
	/// <remarks>
	/// Section 3.2, table 2 <see href="http://vmpcfunction.com/vmpc_mac.pdf">VMPC-MAC: 
	/// A Stream Cipher Based Authenticated Encryption Scheme</see>
	/// </remarks>
	void InitKey(std::vector<byte> &KeyBytes, std::vector<byte> &IvBytes);
};

NAMESPACE_MACEND
#endif