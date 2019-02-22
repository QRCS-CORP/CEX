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
// An implementation of a keyed hash function wrapper; Hash based Message Authentication Code (HMAC).
// Written by John Underhill, September 24, 2014
// Updated October 3, 2016
// Updated February 6, 2018
// Contact: develop@vtdev.com

#ifndef CEX_HMAC_H
#define CEX_HMAC_H

#include "MacBase.h"
#include "IDigest.h"
#include "Digests.h"
#include "SHA2Digests.h"

NAMESPACE_MAC

using Enumeration::Digests;
using Digest::IDigest;
using Enumeration::SHA2Digests;

/// <summary>
/// An implementation of a Hash based Message Authentication Code generator: HMAC
/// </summary>
/// 
/// <example>
/// <description>Generating a MAC code</description>
/// <code>
/// HMAC mac(SHA2Digests::SHA256);
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
/// Only the SHA2-256 AND SHA2-512 hash functions are supported by this implementation. 
/// The cryptographic strength of the HMAC depends upon the strength of the underlying hash function, the size of its hash output, and on the size and quality of the key. \n
/// For example, when using SHA2-256 as the underlying hash function, the generator should be keyed with at least 256 bits (32 bytes) of random key. \n
/// This functionality can be enforced by enabling the CEX_ENFORCE_LEGALKEY definition in the CexConfig file, or by adding that flag to the libraries compilers directives.</para>
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
/// <item><description>This implementation supports the SHA2-256 and SHA2-512 message digests exclusively.</description></item>
/// <item><description>This implementation can utilize a parallelized digest instance for multi-threaded Mac calculations.</description></item>
/// <item><description>The generator must be initialized with a key using the Initialize function before output can be generated.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>If the Parallel parameter of the constructor is set to true, or a parallelized digest instance is loaded, passing an input block of ParallelBlockSize bytes will be processed in parallel.</description></item>
/// <item><description>Sequential mode block size is the underlying hash functions internal input rate-size in bytes.</description></item>
/// <item><description>TagSize size is the MAC functions output code-size in bytes.</description></item>
/// <item><description>The key size should be at least equal to the initialized MAC variants security size, 256 or 512 bits (32 and 64 bytes).</description></item>
/// <item><description>The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code.</description>/></item>
/// <item><description>After a finalizer call the MAC should be re-initialized with a new key.</description></item>
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
class HMAC final : public MacBase
{
private:

	static const std::string CLASS_NAME;
	static const byte IPAD = 0x36;
	static const size_t MINKEY_LENGTH = 8;
	static const size_t MINSALT_LENGTH = 0;
	static const byte OPAD = 0x5C;

	class HmacState;
	std::unique_ptr<IDigest> m_hmacGenerator;
	std::unique_ptr<HmacState> m_hmacState;
	bool m_isDestroyed;
	bool m_isInitialized;

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
	/// <param name="DigestType">The message digest type enumeration name</param>
	/// <param name="Parallel">Initialize the parallelized form of the message digest</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid digest type is selected</exception>
	explicit HMAC(SHA2Digests DigestType, bool Parallel = false);

	/// <summary>
	/// Initialize the class with a digest instance
	/// </summary>
	/// 
	/// <param name="Digest">The message Digest instance</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if the digest instance is null</exception>
	explicit HMAC(IDigest* Digest);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~HMAC() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The MAC generator is ready to process data
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallel processing.</para>
	/// </summary>
	const bool IsParallel();

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	const size_t ParallelBlockSize();

	/// <summary>
	/// Read/Write: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(Degree) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(Degree) function to change the thread count 
	/// and reinitialize the state, or initialize the digest manually using a digest Params structure with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	ParallelOptions &ParallelProfile();

	//~~~Public Functions~~~//

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
	/// Set the number of threads allocated when using multi-threaded tree hashing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads to allocate</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if an invalid degree setting is used</exception>
	void ParallelMaxDegree(size_t Degree);

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
};

NAMESPACE_MACEND
#endif
