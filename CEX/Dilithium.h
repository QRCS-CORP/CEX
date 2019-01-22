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

#ifndef CEX_DILITHIUM_H
#define CEX_DILITHIUM_H

#include "AsymmetricTransforms.h"
#include "IAsymmetricSign.h"
#include "IKdf.h"
#include "AsymmetricKeyPair.h"
#include "DilithiumParameters.h"
#include "AsymmetricKey.h"
#include "AsymmetricKey.h"

NAMESPACE_DILITHIUM

using Enumeration::DilithiumParameters;
using Kdf::IKdf;

/// <summary>
/// An implementation of the Dilithium asymmetric signature scheme
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
/// IAsymmetricKeyPair* kp = sgn.Generate();
/// 
/// // serialize the public key
///	DilithiumPrivateKey* prik = (DilithiumPrivateKey*)kp->PrivateKey();
/// std::vector&lt;byte&gt; pk = prik->ToBytes();
/// </code>
///
/// <description>Sign:</description>
/// <code>
/// Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
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
/// Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
/// sgn.Initialize(PublicKey);
/// std::vector&lt;byte&gt; message(0);
/// bool status;
///
///	// if authentication fails, do something
///	status = sgn.Verify(Signature, msg);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>Dilithium is a digital signature scheme that is strongly secure under chosen message attacks based on the hardness of lattice problems over module lattices. \n
/// The security notion means that an adversary having access to a signing oracle cannot produce a signature of a message whose signature he hasn't yet seen. \n
/// Nor produce a different signature of a message that he already saw signed. 
/// </para>
/// 
/// <list type="bullet">
/// <item><description>There are three available parameter sets dilineated by security strength; medium security: DLMS1256Q8380417, high security: DLMS2N256Q8380417, highest security: DLMS2N256Q8380417</description></item>
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: CipherPublicKey, or CipherPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The message is authenticated using GCM, and throws CryptoAuthenticationFailure on decryption authentication failure</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Software: <a href="https://pq-crystals.org/dilithium/software.shtml">Dilithium</a> Software.</description></item>
/// <item><description>Reference Paper : <a href="https://pq-crystals.org/dilithium/data/dilithium-specification.pdf">CRYSTALS-Dilithium</a>.</description></item>
/// <item><description>Reference: <a href="https://pq-crystals.org/dilithium/data/dilithium-20180114.pdf">Dilithium</a>: A lattice-Based Digital Signature Scheme.</description></item>
/// <item><description>Website: <a href="https://pq-crystals.org/dilithium/">NTRU Prime Website</a></description></item>.
/// </list>
/// </remarks>
class Dilithium final : public IAsymmetricSign
{
private:

	static const std::string CLASS_NAME;

	bool m_isDestroyed;
	bool m_destroyEngine;
	DilithiumParameters m_dlmParameters;
	bool m_isInitialized;
	bool m_isSigner;
	std::unique_ptr<AsymmetricKey> m_privateKey;
	std::unique_ptr<AsymmetricKey> m_publicKey;
	std::unique_ptr<IPrng> m_rndGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Dilithium(const Dilithium&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Dilithium& operator=(const Dilithium&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	Dilithium(DilithiumParameters Parameters = DilithiumParameters::DLMS2N256Q8380417, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using an external Prng instance
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Rng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	Dilithium(DilithiumParameters Parameters, IPrng* Rng);

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~Dilithium() noexcept;

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
	/// <exception cref="CryptoAsymmetricException">Thrown if the key generation call fails</exception>
	AsymmetricKeyPair* Generate() override;

	/// <summary>
	/// Initialize the signature scheme for signing (private key) or verifying (public key)
	/// </summary>
	/// 
	/// <param name="Key">The <see cref="AsymmetricKey"/> containing the Public (verify) or Private (signing) key</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Throws on invalid key or configuration error</exception>
	const void Initialize(AsymmetricKey* Key) override;

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
};

NAMESPACE_DILITHIUMEND
#endif

