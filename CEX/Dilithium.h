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

#ifndef CEX_DILITHIUM_H
#define CEX_DILITHIUM_H

#include "AsymmetricTransforms.h"
#include "IAsymmetricSign.h"
#include "AsymmetricKeyPair.h"
#include "DilithiumParameters.h"
#include "AsymmetricKey.h"
#include "AsymmetricKey.h"

NAMESPACE_DILITHIUM

using Enumeration::DilithiumParameters;

/// <summary>
/// An implementation of the Dilithium asymmetric signature scheme (DILITHIUM)
/// </summary> 
/// 
/// <example>
/// <description>Generate the Public and Private key-pair</description>
/// <code>
/// Dilithium sgn(DilithiumParameters::DLMS2N256Q8380417);
/// IAsymmetricKeyPair* kp = sgn.Generate();
/// 
/// // serialize the public key
///	AsymmetricKey* pubk = kp->PublicKey();
/// std::vector&lt;byte&gt; pk = pubk->ToBytes();
/// </code>
///
/// <description>Sign a message:</description>
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
/// <description>Verify a signature and return the message:</description>
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
/// <description>Introduction:</description>
/// <para>Dilithium is a digital signature scheme that is strongly secure under chosen message attacks based on the hardness of lattice problems over module lattices. \n
/// The security notion means that an adversary having access to a signing oracle cannot produce a signature of a message whose signature he hasn't yet seen, 
/// nor produce a different signature of a message that he already saw signed. \n
/// Dilithium is one of the candidate algorithms submitted to the NIST post-quantum cryptography project. \n
/// </para>
/// <description>Scientific Background:</description>
/// <para>The design of Dilithium is based on the "Fiat-Shamir with Aborts" technique of Lyubashevsky which uses rejection sampling to make lattice-based Fiat-Shamir schemes 
/// compact and secure.The scheme with the smallest signature sizes using this approach is the one of Ducas, Durmus, Lepoint, and Lyubashevsky,
/// which is based on the NTRU assumption and crucially uses Gaussian sampling for creating signatures.
/// Because Gaussian sampling is hard to implement securely and efficiently, we opted to only use the uniform distribution.
/// Dilithium improves on the most efficient scheme that only uses the uniform distribution, due to Bai and Galbraith, by using a new technique that shrinks the public key by more than a factor of 2.</para>
/// <description>:</description>
/// 
/// <list type="bullet">
/// <item><description>There are three available parameter sets dilineated by security strength (S1, S2, S3); medium security: DLMS1N256Q8380417, high security: DLMS2N256Q8380417, highest security: DLMS2N256Q8380417</description></item>
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: CipherPublicKey, or CipherPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The message is authenticated; the Verify function checks the signature and returns false on message authentication failure</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Description: <a href="https://pq-crystals.org/dilithium/index.shtml">Dilithium</a> Introduction.</description></item>
/// <item><description>Software: <a href="https://pq-crystals.org/dilithium/software.shtml">Dilithium</a> Software.</description></item>
/// <item><description>Reference Paper : <a href="https://pq-crystals.org/dilithium/data/dilithium-specification.pdf">CRYSTALS-Dilithium</a>.</description></item>
/// <item><description>Reference: <a href="https://pq-crystals.org/dilithium/data/dilithium-20180114.pdf">Dilithium</a>: A lattice-Based Digital Signature Scheme.</description></item>
/// <item><description>Website: <a href="https://pq-crystals.org/dilithium/">Dilithium Website</a></description></item>.
/// </list>
/// </remarks>
class Dilithium final : public IAsymmetricSign
{
private:

	class DilithiumState;
	std::unique_ptr<DilithiumState> m_dilithiumState;
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
	///
	/// <param name="Parameters">The parameter-set enumeration name</param>
	/// <param name="PrngType">The enumeration name of the seed Prng function to use</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	Dilithium(DilithiumParameters Parameters, Prngs PrngType = Prngs::BCR);

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
	const AsymmetricPrimitives Enumeral() override;

	/// <summary>
	/// Read Only: The signature scheme has been initialized with a key
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Read Only: This class is initialized for Signing with the Private key
	/// </summary>
	const bool IsSigner() override;

	/// <summary>
	/// Read Only: The signature scheme and parameter name
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
	/// <returns>A public/private key-pair</returns>
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
	/// <param name="Message">The byte array containing the message to sign</param>
	/// <param name="Signature">The output signature array containing the signature and message</param>
	/// 
	/// <returns>Returns the size of the signed message</returns>
	size_t Sign(const std::vector<byte> &Message, std::vector<byte> &Signature) override;

	/// <summary>
	/// Verify a signed message and return the message array.
	/// <para>The message returned will be zeroed on authentication failure.</para>
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

