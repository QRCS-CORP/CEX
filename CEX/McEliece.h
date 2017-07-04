// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
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

#ifndef _CEX_MCELIECE_H
#define _CEX_MCELIECE_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "MPKCKeyPair.h"
#include "MPKCParams.h"
#include "MPKCParamSet.h"
#include "MPKCPrivateKey.h"
#include "MPKCPublicKey.h"

NAMESPACE_MCELIECE

using Key::Asymmetric::MPKCKeyPair;
using Enumeration::MPKCParams;
using Key::Asymmetric::MPKCPrivateKey;
using Key::Asymmetric::MPKCPublicKey;

/// <summary>
/// An implementation of the Niederreiter's form of the McEliece public key crypto-system
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// McEliece cpr(MPKCParams:: TODO );
/// IAsymmetricKeyPair* kp = cpr.Generate();
/// // serialize the public key
/// MPKCPublicKey* pubK1 = (MPKCPublicKey*)kp->PublicKey();
/// std:vector&lt;byte&gt; skey = pubK1->ToBytes();
/// </code>
///
/// <description>Encryption:</description>
/// <code>
/// McEliece cpr(Enumeration::MPKCParams::  TODO );
/// cpr.Initialize(true, kp);
/// // no rand input; populates the message when using rlwe reconciliation mode
/// std:vector&lt;byte&gt; enc = cpr.Encrypt(msg);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// McEliece cpr(Enumeration::MPKCParams::Q12289N1024);
/// cpr.Initialize(false, kp);
/// std:vector&lt;byte&gt; dec = cpr.Decrypt(enc);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>.</para>
///
/// <para>.</para>
/// 
/// <list type="bullet">
/// <item><description>The Q12289/N1024 parameter set is the default cipher configuration; as of (1.0.0.3), this is currently the only parameter set, but a modular construction is used anticipating future expansion</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The primary pseudo-random function (message digest) can be set through the constructor (default is SHA2-256)</description></item>
/// <item><description>The default prng used to generate the public key and private keys (default is BCR), is an AES256/CTR-BE construction</description></item>
/// <item><description>The seed authentication and verification engine is fixed at AES256-GCM</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description></description></item>
/// <item><description></description></item>
/// </list>
/// </remarks>
class McEliece final : public IAsymmetricCipher
{
private:

	static const std::string CLASS_NAME;

	bool m_destroyEngine;
	IDigest* m_dgtExtractor;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	bool m_isParallel;
	MPKCParamSet m_paramSet;
	MPKCParams m_mpkcParameters;
	IAsymmetricKeyPair* m_keyPair;
	std::vector<byte> m_keyTag;
	MPKCPrivateKey* m_privateKey;
	MPKCPublicKey* m_publicKey;
	IPrng* m_rndGenerator;

public:

	McEliece() = delete;
	McEliece(const McEliece&) = delete;
	McEliece& operator=(const McEliece&) = delete;
	McEliece& operator=(McEliece&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The cipher type-name
	/// </summary>
	const AsymmetricEngines Enumeral() override;

	/// <summary>
	/// Get: The cipher is initialized for encryption
	/// </summary>
	const bool IsEncryption() override;

	/// <summary>
	/// Get: The cipher has been initialized with a key
	/// </summary>
	const bool IsInitialized() override;

	/// <summary>
	/// Get: The cipher and parameter-set formal names
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Get: The ciphers initialization parameters
	/// </summary>
	const MPKCParamSet &ParamSet();

	/// <summary>
	/// Get: The ciphers parameters enumeration name
	/// </summary>
	const MPKCParams Parameters();

	/// <summary>
	/// Get/Set: A new asymmetric key-pairs optional identification tag.
	/// <para>Setting this value must be done before the Generate method is called.</para>
	/// </summary>
	std::vector<byte> &Tag() override;

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate the cipher with auto-initialized prng and digest functions
	/// </summary>
	///
	/// <param name="Parameters">The cipher parameter enumeration name</param>
	/// <param name="PrngType">The Prng function type</param>
	/// <param name="DigestType">The digest function type</param>
	/// <param name="Parallel">The cipher is multi-threaded</param>
	McEliece(MPKCParams Parameters, Prngs PrngType = Prngs::BCR, Digests DigestType = Digests::SHA256, bool Parallel = false);

	/// <summary>
	/// Instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The ciphers parameter settings type</param>
	/// <param name="Prng">A pointer to the Prng function</param>
	/// <param name="Digest">A pointer to the digest function</param>
	/// <param name="Parallel">The cipher is multi-threaded</param>
	McEliece(MPKCParams Parameters, IPrng* Prng, IDigest* Digest, bool Parallel = false);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~McEliece() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// An exchange has returned (B => M), process the message and generate a shared secret
	/// </summary>
	/// 
	/// <param name="PrivateKey">The originators private-key A</param>
	/// <param name="Message">The return message generated by B</param>
	/// <param name="Secret">The shared secret value</param>
	void Decapsulate(const IAsymmetricKey* PrivateKey, const std::vector<byte> &Message, std::vector<byte> &Secret) override;

	/// <summary>
	/// Decrypt an encrypted cipher-text and return the shared secret
	/// </summary>
	/// 
	/// <param name="Message">The input cipher-text</param>
	/// 
	/// <returns>The decrypted message</returns>
	std::vector<byte> Decrypt(std::vector<byte> &Message) override;

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Received a public key and initiating an exchange (A => Pk), outputting a return message in public-key, and the shared secret
	/// </summary>
	/// 
	/// <param name="Message">The public key sent from A</param>
	/// <param name="Reply">The return message generated by B</param>
	/// <param name="Secret">The shared secret value</param>
	void Encapsulate(const std::vector<byte> &Message, std::vector<byte> &Reply, std::vector<byte> &Secret) override;

	/// <summary>
	/// Encrypt a shared secret and return the encrypted message
	/// </summary>
	/// 
	/// <param name="Secret">The shared secret array</param>
	/// 
	/// <returns>The encrypted message</returns>
	std::vector<byte> Encrypt(std::vector<byte> &Secret) override;

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	/// 
	/// <returns>A public/private key pair</returns>
	IAsymmetricKeyPair* Generate() override;

	/// <summary>
	/// Initialize the cipher for encryption or decryption
	/// </summary>
	/// 
	/// <param name="Encryption">Initialize the cipher for encryption or decryption</param>
	/// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the Public (encrypt) and/or Private (decryption) key</param>
	void Initialize(bool Encryption, IAsymmetricKeyPair* KeyPair) override;

private:

	void Scope();
};

NAMESPACE_MCELIECEEND
#endif
