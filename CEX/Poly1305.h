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
// An implementation of a Stream Cipher based Message Authentication Code (Poly1305).
// Written by John G. Underhill, February 2, 2018
// Updated February 6, 2018
// Contact: develop@vtdev.com

#ifndef CEX_POLY1305_H
#define CEX_POLY1305_H

#include "MacBase.h"
#include "SymmetricKey.h"

NAMESPACE_MAC

/// <summary>
/// An implementation of the Poly1305 Message Authentication Code generator: Poly1305
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// Poly1305 mac;
///
/// SymmetricKey kp(Key);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Poly1305 is a Message Authentication Code generator that return a 16-byte authentication code for a message of any length.
/// This variant uses a a 32-byte secret key to generate an authentication code along with each encrypted message segment.</para>
/// 
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>The generator must be initialized with a key using the Initialize function before output can be generated.</description></item>
/// <item><description>The Initialize(ISymmetricKey) function can use a SymmetricKey or a SymmetricSecureKey key container class containing the generators keying material.</description></item>
/// <item><description>Never reuse a nonce with the Poly1305 Mac, this is insecure and strongly discouraged.</description></item>
/// <item><description>MAC return size is 16 bytes, the array can be can be truncated by the caller.</description></item>
/// <item><description>The Initialize function requires a fixed key-size of 32 bytes (256 bits) in length.</description></item>
/// <item><description>The Compute(Input, Output) method wraps the Update(Input, Offset, Length) and Finalize(Output, Offset) methods and should only be used on small to medium sized data.</description>/></item>
/// <item><description>The Update(Input, Offset, Length) processes any length of message data, and is used in conjunction with the Finalize(Output, Offset) method, which completes processing and returns the finalized MAC code.</description>/></item>
/// <item><description>After a finalizer call the MAC must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>A state of the art message-authentication code: <a href="https://cr.yp.to/mac.html">Poly1305</a>.</description></item>
/// </list>
/// </remarks>
class Poly1305 final : public MacBase
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const size_t POLYKEY_SIZE = 32;
	static const size_t MINSALT_LENGTH = 0;

	class Poly1305State;
	bool m_isInitialized;
	std::unique_ptr<Poly1305State> m_poly1305State;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Poly1305(const Poly1305&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Poly1305& operator=(const Poly1305&) = delete;

	/// <summary>
	/// Initialize the class
	/// </summary>
	Poly1305();

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~Poly1305() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The MAC generator is ready to process data
	/// </summary>
	const bool IsInitialized() override;

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
	/// Uses a key and nonce arrays to initialize the MAC.</para>
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

	static void Absorb(const std::vector<byte> &Output, size_t OutOffset, size_t Length, bool IsFinal, std::unique_ptr<Poly1305State> &State);
};

NAMESPACE_MACEND
#endif
