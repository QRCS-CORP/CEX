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

#ifndef CEX_MCELIECE_H
#define CEX_MCELIECE_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "MPKCKeyPair.h"
#include "MPKCParams.h"
#include "MPKCPrivateKey.h"
#include "MPKCPublicKey.h"

NAMESPACE_MCELIECE

using Key::Asymmetric::MPKCKeyPair;
using Enumeration::MPKCParams;
using Key::Asymmetric::MPKCPrivateKey;
using Key::Asymmetric::MPKCPublicKey;

/// <summary>
/// An implementation of the Niederreiter dual form of the McEliece public key crypto-system
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// McEliece cpr(MPKCParams::M12T62, [PrngType], [CipherType]);
/// IAsymmetricKeyPair* kp = cpr.Generate();
/// // serialize the public key
/// MPKCPublicKey* pubK = (MPKCPublicKey*)kp->PublicKey();
/// std:vector&lt;byte&gt; skey = pubK->ToBytes();
/// </code>
///
/// <description>Encryption:</description>
/// <code>
/// create the shared secret
/// std:vector&lt;byte&gt; msg(64);
/// Prng::IPrng* rng = Helper::PrngFromName::GetInstance(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
/// rng->Generate(msg);
/// // initialize the cipher
/// McEliece cpr(MPKCParams::M12T62, [PrngType], [CipherType]);
/// cpr.Initialize(kp);
/// // encrypt the secret
/// std:vector&lt;byte&gt; enc = cpr.Encrypt(msg);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// // initialize the cipher
/// McEliece cpr(MPKCParams::M12T62, [PrngType], [CipherType]);
/// cpr.Initialize(kp);
/// // decrypt the secret
/// std:vector&lt;byte&gt; msg = cpr.Decrypt(enc);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>.</para>
///
/// <para>This implementation is based on the one written by Daniel Bernstien, Tung Chou, and Peter Schwabe: <a href="https://www.win.tue.nl/~tchou/mcbits/."> 'McBits'</a>. \n
/// The MPKCParams enumeration member is passed to the constructor along with either an optional Prng and block-cipher enum type values, or uninitialized instances of a Prng and a block cipher. \n
/// The Generate function returns a pointer to an IAsymmetricKeyPair container, that holds the public and private keys, along with an optional key tag byte array. \n
/// The encryption method a standard encryption interface: CipherText = Encrypt(Message), the decryption method uses the inverse: Message = Decrypt(CipherText).</para>
/// 
/// <list type="bullet">
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type (AsymmetricKeyTypes: CipherPublicKey, or CipherPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The M12T62 parameter set is the default cipher configuration; as of (1.0.0.4), this is currently the only parameter set, but a modular construction is used anticipating future expansion</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The primary pseudo-random function (message digest) can be set through the constructor (default is SHA2-256)</description></item>
/// <item><description>The default prng used to generate the public key and private keys (default is BCR), is an AES256/CTR-BE construction</description></item>
/// <item><description>The internal seed authentication engine is fixed as a GCM mode, which can use any of the implemented block ciphers, standard or extended</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>//
/// <list type="number">
/// <item><description>the Niederreiter dual form of the McEliece cipher: <a href="https://eprint.iacr.org/2015/610.pdf">McBits</a> a fast constant-time code based cryptography.</description></item>
/// <item><description>McEliece and <a href="https://www.iacr.org/archive/crypto2011/68410758/68410758.pdf">Niederreiter</a> Cryptosystems That Resist Quantum Fourier Sampling Attacks.</description></item>
/// <item><description>Attacking and defending the <a href="https://eprint.iacr.org/2008/318.pdf">McEliece</a> cryptosystem.</description></item>
/// <item><description>Attacking and defending the <a href="https://eprint.iacr.org/2008/318.pdf">McEliece</a> cryptosystem.</description></item>
/// </list>
/// </remarks>
class McEliece final : public IAsymmetricCipher
{
private:

	static const std::string CLASS_NAME;

	bool m_destroyEngine;
	std::vector<byte> m_domainKey;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isInitialized;
	MPKCParams m_mpkcParameters;
	std::unique_ptr<MPKCPrivateKey> m_privateKey;
	std::unique_ptr<MPKCPublicKey> m_publicKey;
	std::unique_ptr<IPrng> m_rndGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	McEliece(const McEliece&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	McEliece& operator=(const McEliece&) = delete;

	/// <summary>
	/// Instantiate the cipher with auto-initialized prng and digest functions
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="PrngType">The seed prng function type; the default is the BCR generator</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if an invalid block cipher type, prng type, or parameter set is specified</exception>
	McEliece(MPKCParams Parameters = MPKCParams::M12T62, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Prng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Thrown if an invalid block cipher, prng, or parameter set is specified</exception>
	McEliece(MPKCParams Parameters, IPrng* Prng);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~McEliece() override;

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
	const MPKCParams Parameters();

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
	/// Generate a shared secret and ciphertext
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
	/// <param name="Key">The asymmetric public or private key</param>
	/// 
	/// <exception cref="Exception::CryptoAsymmetricException">Fails on invalid key or configuration error</exception>
	void Initialize(IAsymmetricKey* Key) override;
};

NAMESPACE_MCELIECEEND
#endif
