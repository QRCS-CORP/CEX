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
// Updated by January 19, 2023
// Contact: develop@qscs.ca

#ifndef CEX_MCELIECE_H
#define CEX_MCELIECE_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "McElieceParameters.h"

NAMESPACE_MCELIECE

using Enumeration::McElieceParameters;

/// <summary>
/// An implementation of the Niederreiter dual form of the McEliece public key crypto-system (MPKC)
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// McEliece cpr(McElieceParameters::MPKCS2N6960T119, [PrngType]);
/// IAsymmetricKeyPair* kp = cpr.Generate();
/// // serialize the public key
/// IAsymmetricKey* pubk = kp->PublicKey();
/// std::vector&lt;uint8_t&gt; skey = pubk->ToBytes();
/// </code>
///
/// <description>Encryption:</description>
/// <code>
/// create the shared secret
/// std::vector&lt;uint8_t&gt; cpt(0);
/// std::vector&lt;uint8_t&gt; ssk(0);
///
/// // initialize the cipher
/// McEliece cpr(McElieceParameters::MPKCS2N6960T119, [PrngType]);
/// cpr.Initialize(PublicKey);
/// // encrypt the secret
/// cpr.Encapsulate(cpt, ssk);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// std::vector&lt;uint8_t&gt; ssk(0);
/// bool status;
///
/// McEliece cpr(McElieceParameters::MPKCS2N6960T119, [PrngType]);
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
/// <para>This implementation was originally written in C by Daniel Bernstien, Tung Chou, and Peter Schwabe: as the NIST PQ Round 3 submission (using the recommended version contained in the SUPERCOP package). \n
/// The McElieceParameters enumeration member is passed to the constructor along with the Prng enum type value (required: the default is BCR), or an initialized instance of a Prng through the secondary advanced constructor option. \n
/// The Generate function returns a pointer to an IAsymmetricKeyPair container, that holds the public and private keys, along with an optional key-tag uint8_t array. \n
/// The encryption method uses an encapsulation KEM interface: Encapsulate(CipherText [out], SharedSecret [out]), the decryption method uses: Decapsulate(CipherText [in], SharedSecret [out]).</para>
///
/// <description>Domain Key:</description>
/// <para>This cipher utilizes an optional two-key system. The KEM shared-secret generated with the encapsulate and decapsulate methods, can be combined with a secondary key. \n
/// This second key can be provided to users within a domain, or as part of a two-key mechanism in which the server component provides one ephemeral key to each host,
/// and the two hosts exchange the second key (the shared-secret) via a second asymmetric key exchange. \n
/// The domain key is used as the customization string in an instance of cSHAKE-512, the ciphers formal name (cipher-name + parameter-name), is used as the cSHAKE name parameter, 
/// and the shared secret is the primary seed. \n
/// Using the domain key, the shared secret output is equal to the initial size of the shared-secret array, this means that in this extended operating mode, secure output of up to 1KB is possible. \n
/// To enable the two-key form of the cipher, populate the DomainKey parameter with the secondary key, and size the shared-secret arrays used in encapsulate and decapsulate to the required output size.
/// In standard operational mode (with a zero-sized domain-key), the output from the cipher is the 256-bit output expected from a standard instance of the cipher.
/// </para>
///
/// <list type="bullet">
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: MPKCPublicKey, or MPKCPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>There are four parameters available: the medium-high security MPKCS3N4608T96 and MPKCS3N6960T119 sets, and the MPKCS4N6688T128 and MPKCS5N8192T128 high-security parameter sets</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The default prng used to generate the public key and private keys (default is BCR), is an auto-seeded AES256/CTR-BE construction</description></item>
/// </list>
/// 
/// <description>
/// <list type="number">
/// <item><description>This version of McEliece aligns with the authors recommended SUPERCOP implementation</description></item>
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

	const size_t SECRET_SIZE = 32;
	class MpkcState;
	std::unique_ptr<MpkcState> m_mpkcState;
	AsymmetricKey* m_privateKey;
	AsymmetricKey* m_publicKey;
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
	McEliece(McElieceParameters Parameters = McElieceParameters::MPKCS3N4608T96, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Prng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	McEliece(McElieceParameters Parameters, IPrng* Prng);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~McEliece() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The expected base cipher-text size in bytes
	/// </summary>
	const size_t CipherTextSize() override;

	/// <summary>
	/// Read/Write: Reads or Sets the Domain Key used as a customization string by cSHAKE to generate the shared secret.
	/// <para>Changing this code will create a unique distribution of the cipher.
	/// The domain key can be used as a secondary secret shared between hosts in an authenticated domain.
	/// The key is used as a customization string to pre-initialize a custom SHAKE function, that conditions the SharedSecret in Encapsulation/Decapsulation.
	/// For best security, the key should be random, secret, and shared only between hosts within a secure domain.
	/// This property is used by the Shared Trust Model secure communications protocol.</para>
	/// </summary>
	std::vector<uint8_t> &DomainKey();

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
	const McElieceParameters Parameters();

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
	/// Decrypt a ciphertext and return the shared secret
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	/// 
	/// <returns>Returns true if decryption is sucesssful</returns>
	bool Decapsulate(const std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret) override;

	/// <summary>
	/// Generate a shared secret and ciphertext
	/// </summary>
	/// 
	/// <param name="CipherText">The output cipher-text</param>
	/// <param name="SharedSecret">The shared secret key</param>
	void Encapsulate(std::vector<uint8_t> &CipherText, std::vector<uint8_t> &SharedSecret) override;

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

private:

	void CXOF(const std::vector<uint8_t> &Domain, const std::vector<uint8_t> &Key, std::vector<uint8_t> &Secret, size_t Rate);

};

NAMESPACE_MCELIECEEND
#endif
