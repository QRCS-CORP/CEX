// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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
// Updated by September 6, 2020
// Contact: develop@qscs.ca

#ifndef CEX_ECDSA_H
#define CEX_ECDSA_H

#include "AsymmetricParameters.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricKey.h"
#include "AsymmetricKey.h"
#include "ECDSAParameters.h"
#include "IAsymmetricSigner.h"
#include "IDigest.h"

NAMESPACE_ECDSA

using Enumeration::ECDSAParameters;
using Digest::IDigest;

/// <summary>
/// An implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA)
/// </summary> 
/// 
/// <example>
/// <description>Generate the Public and Private key-pair</description>
/// <code>
/// ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
/// IAsymmetricKeyPair* kp = sgn.Generate();
/// 
/// // serialize the public key
///	AsymmetricKey* pubk = kp->PublicKey();
/// std::vector&lt;uint8_t&gt; pk = pubk->ToBytes();
/// </code>
///
/// <description>Sign a message:</description>
/// <code>
/// ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
/// sgn.Initialize(PrivateKey);
/// 
/// std::vector&lt;uint8_t&gt; msg(32);
/// std::vector&lt;uint8_t&gt; sig(0);
/// // generate the signature
/// sgn.Sign(msg, sig);
/// </code>
///
/// <description>Verify a signature and return the message:</description>
/// <code>
/// ECDSA sgn(ECDSAParameters::ECDSAS2P25519S);
/// sgn.Initialize(PublicKey);
/// std::vector&lt;uint8_t&gt; message(0);
///
///	// authenticate the signature
///	if (!sgn.Verify(Signature, msg))
/// {
///		//  authentication failed, do something..
/// }
/// </code>
/// </example>
/// 
/// <remarks>
/// Reference implementations :
/// LibSodium by Frank Denis
/// https://github.com/jedisct1/libsodium
/// 
/// curve25519 - donna by Adam Langley
/// https://github.com/agl/curve25519-donna
/// 
/// NaCI by Daniel J.Bernstein, Tanja Lange, Peter Schwabe
/// https://nacl.cr.yp.to
/// 
/// Rewritten for Misra compliance and optimizations by John G.Underhill
/// September 21, 2020
/// </remarks>
class ECDSA final : public IAsymmetricSigner
{
private:

	class ECDSAState;
	std::unique_ptr<ECDSAState> m_ecdsaState;
	AsymmetricKey* m_privateKey;
	AsymmetricKey* m_publicKey;
	std::unique_ptr<IPrng> m_rndGenerator;
	std::unique_ptr<IDigest> m_rndDigest;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ECDSA(const ECDSA&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ECDSA& operator=(const ECDSA&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	///
	/// <param name="Parameters">The parameter-set enumeration name</param>
	/// <param name="PrngType">The enumeration name of the seed Prng function to use</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	ECDSA(ECDSAParameters Parameters, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using an external Prng instance
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Rng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	ECDSA(ECDSAParameters Parameters, IPrng* Rng);

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~ECDSA() noexcept;

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
	/// Read Only: This class has been initialized for Signing with the Private key
	/// </summary>
	const bool IsSigner() override;

	/// <summary>
	/// Read Only: The signature scheme and parameter name, including the loaded parameter-set
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The Private key-size in bytes
	/// </summary>
	const size_t PrivateKeySize() override;

	/// <summary>
	/// Read Only: The Public key-size in bytes
	/// </summary>
	const size_t PublicKeySize() override;

	/// <summary>
	/// Read Only: The base signature size in bytes
	/// </summary>
	const size_t SignatureSize() override;

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
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <param name="Seed">The random seed</param>
	/// 
	/// <returns>A public/private key-pair</returns>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if the key generation call fails</exception>
	AsymmetricKeyPair* Generate(std::vector<uint8_t> &Seed);

	/// <summary>
	/// Initialize the signature scheme for signing (private-key) or verifying (public-key)
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
	/// <param name="Message">The uint8_t array containing the message to sign</param>
	/// <param name="Signature">The output signature array containing the signature and message</param>
	/// 
	/// <returns>Returns the size of the signed message</returns>
	size_t Sign(const std::vector<uint8_t> &Message, std::vector<uint8_t> &Signature) override;

	/// <summary>
	/// Verify a signed message and return the message array.
	/// <para>The message returned will be zeroed on authentication failure.</para>
	/// </summary>
	/// 
	/// <param name="Signature">The output signature array containing the signature and message</param>
	/// <param name="Message">The message uint8_t array containing the data to process</param>
	/// 
	/// <returns>Returns true if the signature matches, false for authentication failure</returns>
	bool Verify(const std::vector<uint8_t> &Signature, std::vector<uint8_t> &Message) override;
};

NAMESPACE_ECDSAEND
#endif

