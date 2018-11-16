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
#include "SHAKE.h"
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
/// The Asymmetric cipher interface
/// </summary>
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
	Sphincs(SphincsParameters Parameters = SphincsParameters::SphincsSK256F256, Prngs PrngType = Prngs::BCR);

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
	/// <param name="AsymmetricKey">The <see cref="AsymmetricKey"/> containing the Public (verify) or Private (signing) key</param>
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
};

NAMESPACE_SPHINCSEND
#endif

