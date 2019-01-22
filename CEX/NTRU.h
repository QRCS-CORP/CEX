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

#ifndef CEX_NTRU_H
#define CEX_NTRU_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "NTRUParameters.h"

NAMESPACE_NTRU

using Enumeration::NTRUParameters;


/// <summary>
/// An implementation of the NTRU Prime asymmetric cipher (NTRU)
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// NTRU acpr(NTRUParameters::NTRUS1LQ4591N761);
/// IAsymmetricKeyPair* kp = acpr.Generate();
/// 
/// // serialize the public key
/// NTRUPublicKey* pubK1 = (NTRUPublicKey*)kp->PublicKey();
/// std::vector&lt;byte&gt; pk = pubK1->ToBytes();
/// </code>
///
/// <description>Encryption:</description>
/// <code>
/// create the shared secret
/// std::vector&lt;byte&gt; cpt(0);
/// std::vector&lt;byte&gt; sec(32);
///
/// // initialize the cipher
/// NTRU acpr(NTRUParameters::NTRUS1LQ4591N761);
/// cpr.Initialize(PublicKey);
/// // encrypt the secret
/// status = cpr.Encrypt(cpt, sec);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// std::vector&lt;byte&gt; sec(32);
/// bool status;
///
/// // initialize the cipher
/// NTRU acpr(NTRUParameters::NTRUS1LQ4591N761);
/// cpr.Initialize(PrivateKey);
/// // decrypt the secret, status returns authentication outcome, false for failure
/// status = cpr.Decrypt(cpt, sec);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>Several ideal-lattice-based cryptosystems have been broken by recent attacks that exploit special structures of the rings used in those cryptosystems. \n
/// The same structures are also used in the leading proposals for post-quantum lattice-based cryptography, including the classic NTRU cryptosystem and typical Ring-LWE-based cryptosystems. \n
/// NTRU Prime tweaks NTRU to use rings without these structures.Here are two public - key cryptosystems in the NTRU Prime family, both designed for the standard goal of IND - CCA2 security:
/// Streamlined NTRU Prime is optimized from an implementation perspective. \n
/// NTRU LPRime (pronounced "ell-prime") is a variant offering different tradeoffs. \n
/// Streamlined NTRU Prime 4591761 and NTRU LPRime 4591761 are Streamlined NTRU Prime and NTRU LPRime with high-security post-quantum parameters.</para>
///
/// <list type="bullet">
/// <item><description>There are two available high-security parameter sets based upon the two rounding forms, L-Prime: NTRUS1LQ4591N761, and S-Prime NTRUS2SQ4591N761 selectable through the class constructor parameter</description></item>
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: NTRUPublicKey, or NTRUPrivateKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The message is authenticated using GCM, and throws CryptoAuthenticationFailure on decryption authentication failure</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Software: <a href="https://ntruprime.cr.yp.to/software.html">NTRU Prime</a> Software.</description></item>
/// <item><description>Reference Paper : <a href="https://ntruprime.cr.yp.to/ntruprime-20160511.pdf">NTRU Prime</a>.</description></item>
/// <item><description>Reference: <a href="https://ntruprime.cr.yp.to/divergence-20180430.pdf">Divergence bounds for random fixed-weight vectors obtained by sorting</a>.</description></item>
/// <item><description>Website: <a href="https://ntruprime.cr.yp.to/">NTRU Prime Website</a></description></item>.
/// </list>
/// </remarks>
class NTRU final : public IAsymmetricCipher
{
private:

	static const std::string CLASS_NAME;

	bool m_destroyEngine;
	std::vector<byte> m_domainKey;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	std::vector<byte> m_keyTag;
	std::unique_ptr<AsymmetricKey> m_privateKey;
	std::unique_ptr<AsymmetricKey> m_publicKey;
	NTRUParameters m_ntruParameters;
	std::unique_ptr<IPrng> m_rndGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	NTRU(const NTRU&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	NTRU& operator=(const NTRU&) = delete;

	/// <summary>
	/// Instantiate the cipher with auto-initialized prng and digest functions
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="PrngType">The seed prng function type; the default is the BCR generator</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng type, or parameter set is specified</exception>
	NTRU(NTRUParameters Parameters = NTRUParameters::NTRUS1LQ4591N761, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Prng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	NTRU(NTRUParameters Parameters, IPrng* Prng);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~NTRU();

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Reads or Sets the Domain Key used as a customization string by cSHAKE to generate the shared secret.
	/// <para>Changing this code will create a unique distribution of the cipher.
	/// The domain key can be used as a secondary secret shared between hosts in an authenticated domain.
	/// The key is used as a customization string to pre-initialize a custom SHAKE function, that conditions the SharedSecret in Encapsulation/Decapsulation.
	/// For best security, the key should be random, secret, and shared only between hosts within a secure domain.
	/// This property is used by the Shared Trust Model secure communications protocol.</para>
	/// </summary>
	std::vector<byte> &DomainKey();

	/// <summary>
	/// Read Only: The cipher type-name
	/// </summary>
	const AsymmetricEngines Enumeral() override;

	/// <summary>
	/// Read Only: The cipher is initialized for encryption
	/// </summary>
	const bool IsEncryption() override;

	/// <summary>
	/// Read Only: The cipher has been initialized with a key
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: The cipher and parameter-set formal names
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The ciphers parameters enumeration name
	/// </summary>
	const NTRUParameters Parameters();

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a ciphertext and return the shared secret
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	/// 
	/// <returns>Returns true if decryption is sucesssful</returns>
	bool Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret) override;

	/// <summary>
	/// Generate a shared secret and ciphertext.
	/// </summary>
	/// 
	/// <param name="CipherText">The output cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	void Encapsulate(std::vector<byte> &CipherText, std::vector<byte> &SharedSecret) override;

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <returns>A public/private key pair</returns>
	AsymmetricKeyPair* Generate() override;

	/// <summary>
	/// Initialize the cipher
	/// </summary>
	/// 
	/// <param name="Key">The asymmetric public or private key</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Throws on invalid key or configuration error</exception>
	void Initialize(AsymmetricKey* Key) override;
};

NAMESPACE_NTRUEND
#endif
