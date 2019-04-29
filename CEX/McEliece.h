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

#ifndef CEX_MCELIECE_H
#define CEX_MCELIECE_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "MPKCParameters.h"

NAMESPACE_MCELIECE

using Enumeration::MPKCParameters;

/// <summary>
/// An implementation of the Niederreiter dual form of the McEliece public key crypto-system
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// McEliece cpr(MPKCParameters::MPKCS1N4096T62, [PrngType], [CipherType]);
/// IAsymmetricKeyPair* kp = cpr.Generate();
/// // serialize the public key
/// MPKCPublicKey* pubK = (MPKCPublicKey*)kp->PublicKey();
/// std::vector&lt;byte&gt; skey = pubK->ToBytes();
/// </code>
///
/// <description>Encryption:</description>
/// <code>
/// create the shared secret
/// std::vector&lt;byte&gt; cpt(0);
/// std::vector&lt;byte&gt; ssk(32);
///
/// // initialize the cipher
/// McEliece cpr(MPKCParameters::MPKCS1N4096T62, Prng-Type);
/// cpr.Initialize(PublicKey);
/// // encrypt the secret
/// cpr.Encapsulate(cpt, ssk);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// std::vector&lt;byte&gt; ssk(32);
/// bool status;
///
/// McEliece cpr(MPKCParameters::MPKCS1N4096T62, Prng-Type);
/// // initialize the cipher
/// cpr.Initialize(PrivateKey);
/// // decrypt the secret, status returns authentication outcome, false for failure
/// status = cpr.Decapsulate(cpt, ssk);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>.</para>
///
/// <para>This implementation is based on two different implementations of the asymmetric primitive; the one written by Daniel Bernstien, Tung Chou, and Peter Schwabe: <a href="https://www.win.tue.nl/~tchou/mcbits/."> 'McBits'</a>,  \n
/// and the NIST PQ Round 2 implementation by the same authors (using the recommended version contained in the SUPERCOP package). \n
/// The MPKCParameters enumeration member is passed to the constructor along with the Prng enum type value (required: the default is BCR), or an initialized instance of a Prng through the secondary advanced constructor option. \n
/// The Generate function returns a pointer to an IAsymmetricKeyPair container, that holds the public and private keys, along with an optional key-tag byte array. \n
/// The encryption method uses an encapsulation KEM interface: Encapsulate(CipherText [out], SharedSecret [out]), the decryption method uses: Decapsulate(CipherText [in], SharedSecret [out]).</para>
/// 
/// <list type="bullet">
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: MPKCPublicKey, or MPKCPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>There are three parameters available: MPKCS1N4096T62 with medium security, MPKCS1N6960T119 with medium-high security, and MPKCS1N8192T128 with high-security</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The default prng used to generate the public key and private keys (default is BCR), is an auto-seeded AES256/CTR-BE construction</description></item>
/// </list>
/// 
/// <description>
/// <list type="number">
/// <item><description>Guiding Publications:</description>//Classic McEliece: <a href="https://classic.mceliece.org/nist/mceliece-20171129.pdf">McEliece</a> conservatice code-based cryptography.</description></item>
/// <item><description>Source code <a href="https://classic.mceliece.org/software.html">Classic McEliece</a> software.</description></item>
/// <item><description>the Niederreiter dual form of the McEliece cipher: <a href="https://eprint.iacr.org/2015/610.pdf">McBits</a> a fast constant-time code based cryptography.</description></item>
/// <item><description>McEliece and <a href="https://www.iacr.org/archive/crypto2011/68410758/68410758.pdf">Niederreiter</a> Cryptosystems That Resist Quantum Fourier Sampling Attacks.</description></item>
/// <item><description>Attacking and defending the <a href="https://eprint.iacr.org/2008/318.pdf">McEliece</a> cryptosystem.</description></item>
/// <item><description>Attacking and defending the <a href="https://eprint.iacr.org/2008/318.pdf">McEliece</a> cryptosystem.</description></item>
/// </list>
/// </remarks>
class McEliece final : public IAsymmetricCipher
{
private:

	class MpkcState;
	std::unique_ptr<MpkcState> m_mpkcState;
	std::unique_ptr<AsymmetricKey> m_privateKey;
	std::unique_ptr<AsymmetricKey> m_publicKey;
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
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng type, or parameter set is specified</exception>
	McEliece(MPKCParameters Parameters = MPKCParameters::MPKCS1N4096T62, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Prng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	McEliece(MPKCParameters Parameters, IPrng* Prng);

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
	const AsymmetricPrimitives Enumeral() override;

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
	const MPKCParameters Parameters();

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
	/// <exception cref="CryptoAsymmetricException">Thrown if the key generation call fails</exception>
	AsymmetricKeyPair* Generate() override;

	/// <summary>
	/// Initialize the cipher
	/// </summary>
	/// 
	/// <param name="Key">The asymmetric public or private key</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Throws on invalid key or configuration error</exception>
	void Initialize(AsymmetricKey* Key) override;
};

NAMESPACE_MCELIECEEND
#endif
