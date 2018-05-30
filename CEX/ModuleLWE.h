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

#ifndef CEX_MODULELWE_H
#define CEX_MODULELWE_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "MLWEKeyPair.h"
#include "MLWEParams.h"
#include "MLWEPrivateKey.h"
#include "MLWEPublicKey.h"

NAMESPACE_MODULELWE

using Key::Asymmetric::MLWEKeyPair;
using Enumeration::MLWEParams;
using Key::Asymmetric::MLWEPrivateKey;
using Key::Asymmetric::MLWEPublicKey;

/// <summary>
/// An implementation of the Module Learning With Errors asymmetric cipher (ModuleLWE)
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// ModuleLWE asycpr(MLWEParams::Q7681N256K3);
/// IAsymmetricKeyPair* kp = asycpr.Generate();
/// 
/// // serialize the public key
/// MLWEPublicKey* pubK1 = (MLWEPublicKey*)kp->PublicKey();
/// std:vector&lt;byte&gt; pk = pubK1->ToBytes();
/// </code>
///
/// <description>Encryption:</description>
/// <code>
/// ModuleLWE asycpr(MLWEParams::Q7681N256K3);
/// asycpr.Initialize(pk);
/// 
/// std:vector&lt;byte&gt; cpt;
/// std:vector&lt;byte&gt; secret(32);
/// // generate the ciphertext and shared secret
/// asycpr.Encapsulate(cpt, secret);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// ModuleLWE asycpr(MLWEParams::Q7681N256K3);
/// asycpr.Initialize(sk);
/// std:vector&lt;byte&gt; secret(32);
/// 
/// try
/// {
/// // decrypt the ciphertext and output the shared secret
///		asycpr.Decapsulate(cpt, secret);
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
/// <para>Module learning with errors (MLWE) is the Learning With Errors problem (a generalization of the parity learning problem), specialized to polynomial arrays over finite fields. \n
/// An important feature of the LWE problem is that the solution may be reducible to the NP-Hard Shortest Vector Problem (SVP) in a Lattice. \n
/// This makes ModuleLWE a strong asymmetric cipher and resistant to currently known attack methods that could use quantum computers.</para>
/// 
/// <list type="bullet">
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type (AsymmetricKeyTypes: CipherPublicKey, or CipherPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The Q12289/N1024 parameter set is the default cipher configuration; as of (1.0.0.3), this is currently the only parameter set, but a modular construction is used anticipating future expansion</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The secondary prng used to generate the public key (BCR), is an AES128/CTR-BE construction, (changed from SHAKE in the Kyber version)</description></item>
/// <item><description>The message is authenticated using GCM, and throws CryptoAuthenticationFailure on decryption authentication failure</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Crystals <a href="https://eprint.iacr.org/2017/634.pdf">Kyber</a> a CCA-secure module-lattice-based KEM.</description></item>
/// <item><description>A Simple, Provably <a href="http://eprint.iacr.org/2012/688.pdf">Secure Key Exchange</a> Scheme Based on the Learning with Errors Problem.</description></item>
/// </list>
/// </remarks>
class ModuleLWE final : public IAsymmetricCipher
{
private:

	static const std::string CLASS_NAME;

	bool m_destroyEngine;
	std::vector<byte> m_domainKey;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	std::unique_ptr<IAsymmetricKeyPair> m_keyPair;
	std::vector<byte> m_keyTag;
	std::unique_ptr<MLWEPrivateKey> m_privateKey;
	std::unique_ptr<MLWEPublicKey> m_publicKey;
	MLWEParams m_mlweParameters;
	std::unique_ptr<IPrng> m_rndGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ModuleLWE(const ModuleLWE&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ModuleLWE& operator=(const ModuleLWE&) = delete;

	/// <summary>
	/// Instantiate the cipher with auto-initialized prng and digest functions
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="PrngType">The seed prng function type; the default is the BCR generator</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if an invalid block cipher type, prng type, or parameter set is specified</exception>
	ModuleLWE(MLWEParams Parameters = MLWEParams::Q7681N256K3, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Prng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if an invalid block cipher, prng, or parameter set is specified</exception>
	ModuleLWE(MLWEParams Parameters, IPrng* Prng);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ModuleLWE();

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
	const MLWEParams Parameters();

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt a ciphertext and return the shared secret.
	/// <para>Uses the Kyber CCA secure key encapsulation method. 
	/// The size of the shared secret is determined by the caller and output through cSHAKE.</para>
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	void Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret) override;

	/// <summary>
	/// Generate a shared secret and ciphertext.
	/// <para>Uses the Kyber CCA secure key encapsulation method. 
	/// The size of the shared secret is determined by the caller and output through cSHAKE.</para>
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
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if the key generation call fails</exception>
	IAsymmetricKeyPair* Generate() override;

	/// <summary>
	/// Initialize the cipher
	/// </summary>
	/// 
	/// <param name="Encryption">Initialize the cipher with a key</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Fails on invalid key or configuration error</exception>
	void Initialize(IAsymmetricKey* Key) override;

private:

	int32_t Verify(const std::vector<byte> &A, const std::vector<byte> &B, size_t Length);
};

NAMESPACE_MODULELWEEND
#endif
