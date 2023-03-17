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
// Updated by September 06, 2020
// Contact: develop@qscs.ca

#ifndef CEX_ECDH_H
#define CEX_ECDH_H

#include "CexDomain.h"
#include "ECDHParameters.h"
#include "IAsymmetricKeyExchange.h"
#include "IDigest.h"

NAMESPACE_ECDH

using Enumeration::ECDHParameters;
using Digest::IDigest;

/// <summary>
/// Contains the primary public api for the Elliptic Curve Diffie Hellman key exchange.
/// </summary> 
/// 
/// <example>
/// <description>Key exchange between 2 parties:</description>
/// <code>
/// ECDH cpr1(ECDHParameters::ECDHS2P25519S);
/// AsymmetricKeyPair* kp1 = cpr1.Generate();
/// 
/// ECDH cpr2(ECDHParameters::ECDHS2P25519S);
/// AsymmetricKeyPair* kp2 = cpr2.Generate();
/// 
/// cpr1.KeyExchange(kp2->PublicKey(), kp1->PrivateKey(), sec1);
/// cpr2.KeyExchange(kp1->PublicKey(), kp2->PrivateKey(), sec2);
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
class ECDH final : public IAsymmetricKeyExchange
{
private:

	class EcdhState;
	std::unique_ptr<EcdhState> m_ecdhState;
	AsymmetricKey* m_privateKey;
	AsymmetricKey* m_publicKey;
	std::unique_ptr<IPrng> m_rndGenerator;
	std::unique_ptr<IDigest> m_rndDigest;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ECDH(const ECDH&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ECDH& operator=(const ECDH&) = delete;

	/// <summary>
	/// Instantiate the cipher with auto-initialized prng and digest functions
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name; the default is S2/K3</param>
	/// <param name="PrngType">The seed prng function type; the default is the BCR (Rijndael-256 CTR) generator</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng type, or parameter set is specified</exception>
	ECDH(ECDHParameters Parameters = ECDHParameters::None, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Prng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	ECDH(ECDHParameters Parameters, IPrng* Prng);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ECDH();

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Reads or Sets the Domain Key used as a customization string by cSHAKE to generate the shared secret.
	/// <para>Changing this code will create a unique distribution of the cipher.
	/// The domain key can be used as a secondary secret shared between hosts in an authenticated domain.
	/// The key is used as a customization string to pre-initialize a custom SHAKE function, that conditions the SharedSecret in Encapsulation/Decapsulation.
	/// For best security, the key should be random, secret, and shared only between hosts within a secure domain.
	/// This property is used by the Shared Trust Model secure communications protocol.</para>
	/// </summary>
	std::vector<uint8_t> &DomainKey() override;

	/// <summary>
	/// Read Only: The cipher type-name
	/// </summary>
	const AsymmetricPrimitives Enumeral() override;

	/// <summary>
	/// Read Only: The cipher and parameter-set formal names
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The ciphers parameters enumeration name
	/// </summary>
	const ECDHParameters Parameters();

	/// <summary>
	/// Read Only: The expected Private key-size in bytes
	/// </summary>
	const size_t PrivateKeySize() override;

	/// <summary>
	/// Read Only: The expected Public key-size in bytes
	/// </summary>
	const size_t PublicKeySize() override;

	/// <summary>
	/// Read Only: The ciphers shared secret output size.
	/// <para>When using the DomainKey parameter, the domain-key is added to the ciphers output shared-secret and used as seed material
	/// by a custom SHAKE-512, this allows for variable length output. In this operating mode, the shared secret can be any size.
	/// In standard operating mode, the output shared-secret is the expected output from the asymmetric cipher.</para>
	/// </summary>
	const size_t SharedSecretSize() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a ciphertext and return the shared secret.
	/// <para>Uses the ECDH CCA secure key encapsulation method. 
	/// The size of the shared secret is determined by the caller and output through cSHAKE.</para>
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	/// 
	/// <returns>Returns true if decryption is sucesssful</returns>
	bool KeyExchange(AsymmetricKey* PublicKey, AsymmetricKey* PrivateKey, std::vector<uint8_t> &SharedSecret) override;

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <returns>A public/private key pair</returns>
	AsymmetricKeyPair* Generate() override;

	/// <summary>
	/// Generate a seeded public/private key-pair
	/// </summary>
	/// 
	/// 
	/// <param name="Seed">A standard vector containing a random seed</param>
	///
	/// <returns>A public/private key pair</returns>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid seed size is used</exception>
	AsymmetricKeyPair* Generate(std::vector<uint8_t> &Seed) override;

private:

	void CXOF(const std::vector<uint8_t> &Domain, const std::vector<uint8_t> &Key, std::vector<uint8_t> &Secret, size_t Rate);
};

NAMESPACE_ECDHEND
#endif
