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
// An implementation of a Stream Cipher based Message Authentication Code (Poly1305).
// Written by John Underhill, November 4, 2017
// Contact: develop@vtdev.com

#ifndef CEX_POLY1305_H
#define CEX_POLY1305_H

#include "IMac.h"
#include "SymmetricKey.h"

NAMESPACE_MAC

/// <summary>
/// An implementation of the Poly1305 Message Authentication Code generator
/// </summary>
/// 
/// <example>
/// <description>Example generating a MAC code from an Input array</description>
/// <code>
/// // the default constructor uses the sequential processing mode (no cipher assist, just Poly1305)
/// Poly1305 mac(Enumeration::BlockCiphers::Rijndael);
///
/// // Note: if key is not pre-conditioned for Poly1305-AES, it will be clamped automatically in Initialize(&ISymmetricKey)
/// SymmetricKey kp(Key);
/// mac.Initialize(kp);
/// mac.Update(Input, 0, Input.size());
/// mac.Finalize(Output, Offset);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>Poly1305 and the cipher assisted variant Poly1305-AES are Message Authentication Code generators that return a 16-byte authentication code for a message of any length.
/// Both variants use a a 32-byte secret key, with the Poly1305-AES mode also requiring a 16-byte nonce (unique message number). \n
/// This MAC generator can be used in tandem with a symmetric cipher, to generate an authentication code along with each encrypted message segment.</para>
/// 
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>This Mac has two modes of operation selected through the constructor; sequential, if no block cipher is selected, or cipher assisted (Poly1305-AES).</description></item>
/// <item><description>This Mac can use any one of the supported base block ciphers: Rijndael, Serpent, or Twofish. HX extended ciphers are not supported at this time.</description></item>
/// <item><description>With Poly1305-AES, the input Mac key is pre-conditioned to speed up multiplication by clearing required bits in the R portion of the key (first 16 bytes).</description></item>
/// <item><description>The Initialize(&ISymmetricKey) function tests the key for pre-conditioning, and if required, will clamp the key automatically..</description></item>
/// <item><description>Never reuse a nonce with the Poly1305 Mac, this is insecure and strongly discouraged.</description></item>
/// <item><description>MAC return size is 16 bytes, the array can be can be truncated by the caller.</description></item>
/// <item><description>The Initialize() function requires a key of 32 bytes (256 bits) in length.</description></item>
/// <item><description>After a finalizer call (Finalize or Compute), the Mac functions state is reset and must be re-initialized with a new key.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>The <a href="https://cr.yp.to/mac/poly1305-20050329.pdf">Poly1305-AES</a> message-authentication code.</description></item>
/// <item><description>A state of the art message-authentication code: <a href="https://cr.yp.to/mac.html">Poly1305</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">AES Fips 197</a>.</description></item>
/// <item><description>Serpent: <a href="http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf">Specification</a>.</description></item>
/// <item><description>Twofish: <a href="https://www.schneier.com/paper-twofish-paper.pdf">Specification</a>.</description></item>
/// </list>
/// </remarks>
class Poly1305 final : public IMac
{
private:

	static const size_t BLOCK_SIZE = 16;
	static const std::string CLASS_NAME;
	static const size_t KEY_SIZE = 32;

	bool m_isDestroyed;
	bool m_isInitialized;
	std::vector<SymmetricKeySize> m_legalKeySizes;
	std::array<uint64_t, 8> m_macState;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;

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
	/// Initialize the class with the block cipher enumeration name
	/// </summary>
	///
	/// <param name="BlockCipherType">The block cipher enumeration name</param>
	/// <param name="CipherExtensionType">The extended HX ciphers key schedule KDF</param>
	/// 
	/// <exception cref="CryptoMacException">Thrown if an invalid block cipher type is selected</exception>
	Poly1305();

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~Poly1305() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Macs internal blocksize in bytes
	/// </summary>
	const size_t BlockSize() override;

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
	/// Read Only: Size of returned mac in bytes
	/// </summary>
	const size_t MacSize() override;

	/// <summary>
	/// Read Only: Mac generators class name
	/// </summary>
	const std::string Name() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Process an input array and return the Mac code in the output array.
	/// <para>After calling this function the Mac code and buffer are zeroised, but key is still loaded.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input data byte array</param>
	/// <param name="Output">The output Mac code array</param>
	void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) override;

	/// <summary>
	/// Process the data and return a Mac code
	/// <para>After calling this function the Mac code and buffer are zeroised, but key is still loaded.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output Mac code array</param>
	/// <param name="OutOffset">The offset in the output array</param>
	/// 
	/// <returns>The number of bytes processed</returns>
	size_t Finalize(std::vector<byte> &Output, size_t OutOffset) override;

	/// <summary>
	/// Initialize the MAC generator with a symmetric key container.
	/// <para>Uses a key, and optional info arrays to initialize the MAC.
	/// In a Poly1305-AES configuration, the R portion of the key is tested for pre-configuration and clamped automatically.
	/// The key size must be one of the block ciphers legal key sizes.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey key container class</param>
	/// 
	/// <exception cref="Exception::CryptoMacException">Thrown if an invalid keyk size is used</exception>
	void Initialize(ISymmetricKey &KeyParams) override;

	/// <summary>
	/// Reset to the default state; Mac code and buffer are zeroised, but key is still loaded
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

	void Process(const std::vector<byte> &Output, size_t OutOffset, size_t Length, bool IsFinal);
};

NAMESPACE_MACEND
#endif
