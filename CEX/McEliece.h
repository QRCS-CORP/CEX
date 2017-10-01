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
#include "BlockCiphers.h"
#include "IAeadMode.h"
#include "IBlockCipher.h"
#include "IDigest.h"
#include "MPKCKeyPair.h"
#include "MPKCParams.h"
#include "MPKCParamSet.h"
#include "MPKCPrivateKey.h"
#include "MPKCPublicKey.h"

NAMESPACE_MCELIECE

using Enumeration::BlockCiphers;
using Cipher::Symmetric::Block::Mode::IAeadMode;
using Cipher::Symmetric::Block::IBlockCipher;
using Digest::IDigest;
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
/// rng->GetBytes(msg);
/// // initialize the cipher
/// McEliece cpr(MPKCParams::M12T62, [PrngType], [CipherType]);
/// cpr.Initialize(true, kp);
/// // encrypt the secret
/// std:vector&lt;byte&gt; enc = cpr.Encrypt(msg);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// // initialize the cipher
/// McEliece cpr(MPKCParams::M12T62, [PrngType], [CipherType]);
/// cpr.Initialize(false, kp);
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
/// The Initialize(bool, *IAsymmetricKeyPair) function takes a boolean indicating initialization type (encryption/decryption), and a pointer to an IAsymmetricKeyPair,
/// (only the required key type need be populated, public or private key).
/// The encryption method a standard encryption interface: CipherText = Encrypt(Message), the decryption method uses the inverse: Message = Decrypt(CipherText).</para>
/// 
/// <list type="bullet">
/// <item><description>The M12T62 parameter set is the default cipher configuration; as of (1.0.0.4), this is currently the only parameter set, but a modular construction is used anticipating future expansion</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The primary pseudo-random function (message digest) can be set through the constructor (default is SHA2-256)</description></item>
/// <item><description>The default prng used to generate the public key and private keys (default is BCR), is an AES256/CTR-BE construction</description></item>
/// <item><description>The internal seed authentication engine is fixed as a GCM mode, which can use any of the implemented block ciphers, standard or extended</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>//
/// <list type="number">
/// <item><description>the Niederreiter dual form of the McEliece: <a href="https://eprint.iacr.org/2015/610.pdf">McBits</a> a fast constant-time code based cryptography.</description></item>
/// <item><description>McEliece and <a href="https://www.iacr.org/archive/crypto2011/68410758/68410758.pdf">Niederreiter</a> Cryptosystems That Resist Quantum Fourier Sampling Attacks.</description></item>
/// <item><description>Attacking and defending the <a href="https://eprint.iacr.org/2008/318.pdf">McEliece</a> cryptosystem.</description></item>
/// <item><description>Attacking and defending the <a href="https://eprint.iacr.org/2008/318.pdf">McEliece</a> cryptosystem.</description></item>
/// </list>
/// </remarks>
class McEliece final : public IAsymmetricCipher
{
private:

	static const std::string CLASS_NAME;
	static const size_t NONCE_SIZE = 16;
	static const size_t TAG_SIZE = 16;

	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isEncryption;
	bool m_isExtended;
	bool m_isInitialized;
	IAeadMode* m_cprMode;
	IAsymmetricKeyPair* m_keyPair;
	IDigest* m_msgDigest;
	std::vector<byte> m_keyTag;
	MPKCParams m_mpkcParameters;
	MPKCParamSet m_paramSet;
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
	explicit McEliece(MPKCParams Parameters, Prngs PrngType = Prngs::BCR, BlockCiphers CipherType = BlockCiphers::Rijndael);

	/// <summary>
	/// Instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The ciphers parameter settings type</param>
	/// <param name="Prng">A pointer to the Prng function</param>
	/// <param name="Digest">A pointer to the digest function</param>
	/// <param name="Parallel">The cipher is multi-threaded</param>
	McEliece(MPKCParams Parameters, IPrng* Prng, IBlockCipher* Cipher);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~McEliece() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt an encrypted cipher-text and return the shared secret
	/// </summary>
	/// 
	/// <param name="Message">The input cipher-text</param>
	/// 
	/// <returns>The decrypted message</returns>
	std::vector<byte> Decrypt(std::vector<byte> &CipherText) override;

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Encrypt a shared secret and return the encrypted message
	/// </summary>
	/// 
	/// <param name="Message">The shared secret array</param>
	/// 
	/// <returns>The encrypted message</returns>
	std::vector<byte> Encrypt(std::vector<byte> &Message) override;

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

	int MPKCDecrypt(std::vector<byte> &Message, const std::vector<byte> &CipherText, const std::vector<byte> &PrivateKey);
	int MPKCEncrypt(std::vector<byte> &CipherText, const std::vector<byte> &Message, const std::vector<byte> &PublicKey, Prng::IPrng* Random);
	void Scope();
};

NAMESPACE_MCELIECEEND
#endif
