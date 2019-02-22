// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// 
// Implementation Details:
// An implementation of a Cipher based Message Authentication Code (CMAC).
// Written by John Underhill, January 10, 2014
// Updated December 20, 2016
// Updated December 23, 2018
// Updated February 6, 2018
// Contact: develop@vtdev.com

#ifndef CEX_CMAC_H
#define CEX_CMAC_H

#include "MacBase.h"
#include "BlockCiphers.h"
#include "CBC.h"

NAMESPACE_MAC

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Cipher::Block::Mode::CBC;
using Cipher::Block::IBlockCipher;
using Cipher::SymmetricKey;

/// <summary>
/// An implementation of a symmetric Cipher based Message Authentication Code generator: CMAC
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// CMAC mac(BlockCiphers::AES);
/// SymmetricKey kp(Key);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Cipher-based Message Authentication Code (CMAC), sometimes known as OMAC, is a block cipher-based message authentication code generator. \n
/// It can use any of the block ciphers in this library as the underlying permutation function run in CBC mode, and provides assurance of message authenticity and the integrity of binary data.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>CIPH</B>=encryption-function, <B>K</B>=key, <B>b</B>=block-size, <B>M</B>=message, <B>K1,K2</B>=subkeys, <B>^</B>=XOR, <B>ls</B>=left-shift</para>
/// <para><EM>Subkey Generation</EM> \n
/// 1) Let L = CIPHK(0b). \n
/// 2)	 If MSB1(L) = 0, then K1 = L ls 1; \n
/// Else K1 = (L ls 1) ^ Rb \n
/// 3)	 If MSB1(K1) = 0, then K2 = K1 ls 1; \n
/// Else K2 = (K1 ls 1) ^ Rb.</para>
///
/// <para><EM>MAC Function</EM> \n
/// 1) Apply the subkey generation process to K to produce K1 and K2. \n
/// 2) If Mlen = 0, let n = 1; else, let n = ⎡Mlen / b⎤. \n
/// 3) Let M1, M2, ..., Mn - 1, Mn*, denote the unique sequence of bit strings such that M = M1 || M2 || ... || Mn - 1 || Mn*, where M1, M2, ..., Mn - 1 are complete blocks. \n
/// 4) If Mn* is a complete block, let Mn = K1 ^ Mn*; else, let Mn = K2 ^ (Mn* || 10j), where j = nb - Mlen - 1. \n
/// 5) Let C0 = 0b. \n
/// 6) For i = 1 to n, let Ci = CIPHK(Ci - 1 ^ Mi). \n
/// 7) Let T = MSBTlen(Cn). \n
/// 8) Return T.</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Never reuse a ciphers key for the CMAC function, this is insecure and strongly discouraged.</description></item>
/// <item><description>MAC tag return size is the underlying ciphers block-size, in this library that is always 16 bytes, this length can be truncated by the caller, but that is not recommended.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize function before output can be generated.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code.</description>/></item>
/// <item><description>After a finalizer call the MAC must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">SP800-38B</a>: The CMAC Mode for Authentication.</description></item>
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc4493">4493</a>: The AES-CMAC Algorithm.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf">Rijndael ammended</a>.</description></item>
/// </list>
/// </remarks>
class CMAC final : public MacBase
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const byte CMAC_FINAL = 0x80;
	static const size_t MINKEY_LENGTH = 16;
	static const size_t MINSALT_LENGTH = 16;
	static const byte MIX_C128 = 0x87;
	static const byte MIX_C64 = 0x1b;

	class CmacState;
	std::unique_ptr<CBC> m_cbcMode;
	std::unique_ptr<CmacState> m_cmacState;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::unique_ptr<SymmetricKey> m_luKey;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CMAC(const CMAC&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CMAC& operator=(const CMAC&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	CMAC() = delete;

	/// <summary>
	/// Initialize the class with the block cipher type enumeration name
	/// </summary>
	///
	/// <param name="CipherType">The block cipher type enumeration name</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid block cipher type is selected</exception>
	explicit CMAC(BlockCiphers CipherType);

	/// <summary>
	/// Initialize this class with a block cipher instance
	/// </summary>
	///
	/// <param name="Cipher">An uninitialized instance of the block-cipher</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the block cipher is null</exception>
	explicit CMAC(IBlockCipher* Cipher);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CMAC() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The block cipher engine type
	/// </summary>
	const BlockCiphers CipherType();

	/// <summary>
	/// Read Only: The MAC generator is ready to process data
	/// </summary>
	const bool IsInitialized() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Reset the CMAC and internal CBC state
	/// </summary>
	void Clear();

	/// <summary>
	/// Process a vector of bytes and return the MAC code
	/// </summary>
	///
	/// <param name="Input">The input vector to process</param>
	/// <param name="Output">The output vector containing the MAC code</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Completes processing and returns the MAC code in a standard-vector
	/// </summary>
	///
	/// <param name="Output">The output standard-vector receiving the MAC code</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	///
	/// <returns>The size of the MAC code in bytes</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Completes processing and returns the MAC code in a secure-vector
	/// </summary>
	///
	/// <param name="Output">The output secure-vector receiving the MAC code</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	///
	/// <returns>The size of the MAC code in bytes</returns>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the output array is too small</exception>
	size_t Finalize(SecureVector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the MAC generator with an ISymmetricKey key container.
	/// <para>Can accept either the SymmetricKey or SymmetricSecureKey container to load keying material.
	/// Uses a key, salt, and info arrays to initialize the MAC.</para>
	/// </summary>
	/// 
	/// <param name="Parameters">An ISymmetricKey key interface, which can accept either a SymmetricKey or SymmetricSecureKey container</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the key is not a legal size</exception>
	void Initialize(ISymmetricKey &Parameters) override;

	/// <summary>
	/// Reset internal state to the pre-initialization defaults.
	/// <para>Internal state is zeroised, and MAC generator must be reinitialized again before being used.</para>
	/// </summary>
	void Reset() override;

	/// <summary>
	/// Update the Mac with a length of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input data vector to process</param>
	/// <param name="InOffset">The starting position with the input array</param>
	/// <param name="Length">The length of data to process in bytes</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the mac is not initialized or the input array is too small</exception>
	void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override;

private:

	static void DoubleLu(const std::vector<byte> &Input, std::vector<byte> &Output);
	static void Pad(std::vector<byte> &Input, size_t Offset, size_t Length);
	static uint ShiftLeft(const std::vector<byte> &Input, std::vector<byte> &Output);
};

NAMESPACE_MACEND
#endif
