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

#ifndef CEX_SPHINCS_H
#define CEX_SPHINCS_H

#include "IAsymmetricSign.h"
#include "IKdf.h"
#include "SphincsKeyPair.h"
#include "SphincsParameters.h"
#include "SphincsPrivateKey.h"
#include "SphincsPublicKey.h"

NAMESPACE_SPHINCS

using Kdf::IKdf;
using Key::Asymmetric::SphincsKeyPair;
using Enumeration::SphincsParameters;
using Key::Asymmetric::SphincsPrivateKey;
using Key::Asymmetric::SphincsPublicKey;

/// <summary>
/// An implementation of the SPHINCS+ asymmetric signature scheme
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// Sphincs sgn(SphincsParameters::SPXS128F256);
/// IAsymmetricKeyPair* kp = sgn.Generate();
/// 
/// // serialize the public key
///	SphincsPrivateKey* prik = (SphincsPrivateKey*)kp->PrivateKey();
/// std::vector&lt;byte&gt; pk = prik->ToBytes();
/// </code>
///
/// <description>Sign:</description>
/// <code>
/// Sphincs sgn(SphincsParameters::SPXS128F256);
/// sgn.Initialize(PrivateKey);
/// 
/// std::vector&lt;byte&gt; msg(32);
/// std::vector&lt;byte&gt; sig(0);
/// // generate the signature
/// sgn.Sign(msg, sig);
/// </code>
///
/// <description>Verify:</description>
/// <code>
/// Sphincs sgn(SphincsParameters::SPXS128F256);
/// sgn.Initialize(PublicKey);
/// std::vector&lt;byte&gt; message(0);
/// 
/// try
/// {
///		// if authentication fails, this will throw
///		sgn.Verify(Signature, msg);
/// }
/// catch (const CryptoAuthenticationFailure &ex)
/// {
///		// handle the authentication failure
/// }
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>SPHINCS+ is a high-security post-quantum stateless hash-based signature scheme that signs hundreds of messages per second on a modern 4-core 3.5GHz Intel CPU. \n
/// Signatures are 41 KB, public keys are 1 KB, and private keys are 1 KB. \n
/// SPHINCS-256 is designed to provide long-term 2128 security even against attackers equipped with quantum computers. \n
/// Unlike most hash-based signature schemes, SPHINCS-256 is stateless, allowing it to be a drop-in replacement for current signature schemes.</para>
/// 
/// <list type="bullet">
/// <item><description>There are three available parameter sets using the 'fast' version of the algorithm dilineated by the core hashing function SHAKE; the SHAKE128 based SPXS128F256, SPXS256F256 using SHAKE256, and the experimental SPXS512F256 using SHAKE512, selectable through the class constructor parameter</description></item>
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: CipherPublicKey, or CipherPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The message is authenticated using GCM, and throws CryptoAuthenticationFailure on decryption authentication failure</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Software: SPHINCS+<a href="https://sphincs.org/software.html">Software</a> .</description></item>
/// <item><description>Reference Paper : SPHINCS+ <a href="https://sphincs.org/data/sphincs+-specification.pdf">Specification</a>.</description></item>
/// <item><description>Reference: <a href="https://eprint.iacr.org/2014/795.pdf">SPHINCS: practical stateless hash-based signatures</a>.</description></item>
/// <item><description>Website: <a href="https://sphincs.org/">NTRU Prime Website</a></description></item>.
/// </list>
/// </remarks>
class Sphincs final : public IAsymmetricSign
{
private:

	static const std::string CLASS_NAME;

	bool m_isDestroyed;
	bool m_destroyEngine;
	bool m_isInitialized;
	bool m_isSigner;
	std::unique_ptr<IKdf> m_kdfGenerator;
	std::unique_ptr<IAsymmetricKeyPair> m_keyPair;
	std::unique_ptr<SphincsPrivateKey> m_privateKey;
	std::unique_ptr<SphincsPublicKey> m_publicKey;
	std::unique_ptr<IPrng> m_rndGenerator;
	SphincsParameters m_spxParameters;

public:

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Sphincs(const Sphincs&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Sphincs& operator=(const Sphincs&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	/// 
	/// <param name="Parameters">The SPHINCS+ parameter set; default is SPXF256</param>
	/// <param name="PrngType">The random prng provider; default is Block-cipher Counter Rng (BCR)</param>
	Sphincs(SphincsParameters Parameters = SphincsParameters::SPXS256F256, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using an external Prng instance
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Rng">A pointer to the seed Prng function</param>
	/// <param name="Generator">The internal kdf generator</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	Sphincs(SphincsParameters Parameters, IPrng* Rng, IKdf* Generator);

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~Sphincs() noexcept;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The signature schemes type-name
	/// </summary>
	const AsymmetricEngines Enumeral() override;

	/// <summary>
	/// Read Only: The signature scheme has been initialized with a key
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: This class is initialized for Signing with the Private key
	/// </summary>
	const bool IsSigner() override;

	/// <summary>
	/// Read Only: The signature scheme name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The expected Private key size in bytes
	/// </summary>
	const size_t PrivateKeySize() override;

	/// <summary>
	/// Read Only: The expected Public key size in bytes
	/// </summary>
	const size_t PublicKeySize() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <returns>A public/private key pair</returns>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if the key generation call fails</exception>
	IAsymmetricKeyPair* Generate() override;

	/// <summary>
	/// Initialize the signature scheme for signing (private key) or verifying (public key)
	/// </summary>
	/// 
	/// <param name="Key">The <see cref="AsymmetricKey"/> containing the Public (verify) or Private (signing) key</param>
	const void Initialize(IAsymmetricKey* Key) override;

	/// <summary>
	/// Sign a message array and return the message and attached signature
	/// </summary>
	/// 
	/// <param name="Message">The message byte array containing the data to process</param>
	/// <param name="Signature">The output signature array containing the signature and message</param>
	/// 
	/// <returns>Returns the size of the signed message</returns>
	size_t Sign(const std::vector<byte> &Message, std::vector<byte> &Signature) override;

	/// <summary>
	/// Verify a signed message and return the message array
	/// </summary>
	/// 
	/// <param name="Signature">The output signature array containing the signature and message</param>
	/// <param name="Message">The message byte array containing the data to process</param>
	/// 
	/// <returns>Returns true if the signature matches</returns>
	bool Verify(const std::vector<byte> &Signature, std::vector<byte> &Message) override;

	void Test();
};

NAMESPACE_SPHINCSEND
#endif

