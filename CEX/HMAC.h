// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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
// An implementation of a keyed hash function wrapper; Hash based Message Authentication Code (HMAC).
// Written by John Underhill, September 24, 2014
// Updated October 3, 2016
// Contact: develop@vtdev.com

#ifndef CEX_HMAC_H
#define CEX_HMAC_H

#include "IMac.h"
#include "IDigest.h"
#include "Digests.h"
#include "SHA2Digests.h"

NAMESPACE_MAC

using Enumeration::Digests;
using Digest::IDigest;
using Enumeration::SHA2Digests;

/// <summary>
/// An implementation of a Hash based Message Authentication Code generator
/// </summary>
/// 
/// <example>
/// <description>Generating a MAC code</description>
/// <code>
/// HMAC mac(Enumeration::BlockCiphers::AHX);
/// SymmetricKey kp(Key);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>A keyed Hash Message Authentication Code (HMAC) uses a cryptographic hash function with a secret key to verify data integrity and authenticate a message. \n
/// Any cryptographic hash function may be used in the calculation of an HMAC, including any of the hash functions implemented in this library. 
/// The cryptographic strength of the HMAC depends upon the strength of the underlying hash function, the size of its hash output, and on the size and quality of the key.</para>
/// 
/// <description><B>Description:</B></description>
/// <para><EM>Legend:</EM> \n 
/// <B>H</B>=hash-function, <B>K</B>=key, <B>K'</B>=derived-key, <B>m</B>=message, <B>^</B>=XOR, <B>||</B>=concatonate \n
/// <EM>Generate</EM> \n
/// Where opad is the outer padding (0x5c...5c), and ipad is the inner padding (0x36...36), and K' is a secret key, derived from key K. \n
/// HMAC(K,m) = H((K' ^ opad) || H(K' ^ ipad) || m))</para> \n
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>This implementation only supports the SHA2-256 and SHA2-512 message digests.</description></item>
/// <item><description>This implementation can utilize a parallelized digest instance for multi-threaded Mac calculations.</description></item>
/// <item><description>If the Parallel parameter of the constructor is set to true, or a parallelized digest instance is loaded, passing an input block of ParallelBlockSize bytes will be processed in parallel.</description></item>
/// <item><description>Sequential mode block size is the underlying hash functions internal block size in bytes.</description></item>
/// <item><description>Digest size is the hash functions output code size in bytes.</description></item>
/// <item><description>The key size should be equal or greater than the digests output size, and less or equal to the block-size.</description></item>
/// <item><description>The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which returns the final MAC code.</description>/></item>
/// <item><description>After a finalizer call (Finalize or Compute), the Mac functions state is reset and must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc2104">2104</a>: HMAC: Keyed-Hashing for Message Authentication.</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf">198-1</a>: The Keyed-Hash Message Authentication Code (HMAC).</description></item>
/// <item><description>Fips <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">180-4</a>: Secure Hash Standard (SHS).</description></item>
/// <item><description>CRYPTO '06, Lecture <a href="http://cseweb.ucsd.edu/~mihir/papers/hmac-new.pdf">NMAC and HMAC Security</a>: NMAC and HMAC Security Proofs.</description></item>
/// </list>
/// </remarks>
class HMAC final : public IMac
{
private:

	static const std::string CLASS_NAME;
	static const byte IPAD = 0x36;
	static const byte OPAD = 0x5C;
	static const size_t MIN_KEYSIZE = 4;

	bool m_destroyEngine;
	std::unique_ptr<IDigest> m_dgtEngine;
	std::vector<byte> m_inputPad;
	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	Digests m_msgDigestType;
	std::vector<byte> m_outputPad;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	HMAC(const HMAC&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	HMAC& operator=(const HMAC&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	HMAC() = delete;

	/// <summary>
	/// Constructor: instantiate this class using the digest enumeration name
	/// </summary>
	/// 
	/// <param name="DigestType">The message digest enumeration name</param>
	/// <param name="Parallel">Initialize the parallelized form of the message digest</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid digest type is selected</exception>
	explicit HMAC(SHA2Digests DigestType, bool Parallel = false);

	/// <summary>
	/// Initialize the class with a digest instance
	/// </summary>
	/// 
	/// <param name="Digest">Message Digest instance</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if the digest is null</exception>
	explicit HMAC(IDigest* Digest);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~HMAC() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Digests internal blocksize in bytes
	/// </summary>
	const size_t BlockSize() override;

	/// <summary>
	/// Read Only: The message digest engine type
	/// </summary>
	const Digests DigestType();

	/// <summary>
	/// Read Only: Mac generators type name
	/// </summary>
	const Macs Enumeral() override;

	/// <summary>
	/// Read Only: Mac is ready to digest data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Recommended Mac key sizes in a SymmetricKeySize array
	/// </summary>
	std::vector<SymmetricKeySize> LegalKeySizes() const override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	const bool IsParallel();

	/// <summary>
	/// Read Only: Size of returned mac in bytes
	/// </summary>
	const size_t TagSize() override;

	/// <summary>
	/// Read Only: Mac generators implementation name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize();

	/// <summary>
	/// Read/Write: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state, or initialize the digest manually using a digest Params structure with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	ParallelOptions &ParallelProfile();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process an input array and return the Mac code in the output array.
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input data byte array</param>
	/// <param name="Output">The output Mac code array</param>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Process the data and return a Mac code
	/// <para>After calling this function the Macs state is reset and must be re-initialized with a new key.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output Mac code array</param>
	/// <param name="OutOffset">The offset in the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the MAC generator with a SymmetricKey key container.
	/// <para>Uses a key array to initialize the MAC.
	/// The key size should be one of the LegalKeySizes; the digests input block size is recommended.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey key container class</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if an invalid key size is used</exception>
	void Initialize(ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoDigestException">Thrown if an invalid degree setting is used</exception>
	void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Reset to the default state; Mac must be re-initialized after this call
	/// </summary>
	void Reset() override;

	/// <summary>
	/// Update the Mac with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte to process</param>
	void Update(byte Input) override;

	/// <summary>
	/// Update the Mac with a block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input data array to process</param>
	/// <param name="InOffset">Starting position with the input array</param>
	/// <param name="Length">The length of data to process in bytes</param>
	void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) override;

private:

	void Scope();
	void XorPad(std::vector<byte> &A, byte N);
};

NAMESPACE_MACEND
#endif
