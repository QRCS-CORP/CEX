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

#ifndef CEX_NTRUPRIME_H
#define CEX_NTRUPRIME_H

#include "CexDomain.h"
#include "IAsymmetricCipher.h"
#include "NTRUParameters.h"

NAMESPACE_NTRUPRIME

using Enumeration::NTRUParameters;


/// <summary>
/// An implementation of the NTRU-Prime asymmetric cipher (NTRUPRIME)
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// NTRUPrime cpr(NTRUParameters::NTRUS2SQ4591N761);
/// IAsymmetricKeyPair* kp = cpr.Generate();
/// 
/// // serialize the public key
/// IAsymmetricKey* pubk = kp->PublicKey();
/// std::vector&lt;byte&gt; pk = pubk->ToBytes();
/// </code>
///
/// <description>Encryption:</description>
/// <code>
/// create the shared secret
/// std::vector&lt;byte&gt; cpt(0);
/// std::vector&lt;byte&gt; sec(0);
///
/// // initialize the cipher
/// NTRUPrime cpr(NTRUParameters::NTRUS2SQ4591N761);
/// cpr.Initialize(PublicKey);
/// // generate the ciphertext and shared secret
/// status = cpr.Encapsulate(cpt, sec);
/// </code>
///
/// <description>Decryption:</description>
/// <code>
/// std::vector&lt;byte&gt; sec(0);
/// bool status;
///
/// // initialize the cipher
/// NTRUPrime cpr(NTRUParameters::NTRUS2LQ4591N761);
/// cpr.Initialize(PrivateKey);
/// // decrypt the shared secret, status returns authentication outcome, false for failure
/// status = cpr.Decapsulate(cpt, sec);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <para>Several ideal-lattice-based cryptosystems have been broken by recent attacks that exploit special structures of the rings used in those cryptosystems. \n
/// The same structures are also used in the leading proposals for post-quantum lattice-based cryptography, including the classic NTRU cryptosystem and typical Ring-LWE-based cryptosystems. \n
/// NTRU-Prime tweaks NTRU to use rings without these structures. This implementation uses three parameter sets from the Streamlined NTRU-Prime implementations; optimized from an implementation perspective. \n
/// Streamlined NTRU SPrime Q4621P653, Q4591P761, and Q5167P857 are the medium, high, and highest-security post-quantum-secure parameters. \n
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
/// <item><description>This version of NTRU-Prime aligns with the NIST PQ round 2 implementation</description></item>
/// <item><description>There are three available parameter sets based upon the streamlined rounding form; Q4621P653, Q4591P761, and Q5167P857, selectable through the class constructor parameter</description></item>
/// <item><description>The ciphers operating mode (encryption/decryption) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: NTRUPublicKey, or NTRUPrivateKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>The message is authenticated using SHAKE, and throws CryptoAuthenticationFailure on decryption authentication failure</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Software: <a href="https://ntruprime.cr.yp.to/software.html">NTRU-Prime</a> Software.</description></item>
/// <item><description>Reference Paper : <a href="https://ntruprime.cr.yp.to/ntruprime-20160511.pdf">NTRU-Prime</a>.</description></item>
/// <item><description>Reference: <a href="https://ntruprime.cr.yp.to/divergence-20180430.pdf">Divergence bounds for random fixed-weight vectors obtained by sorting</a>.</description></item>
/// <item><description>Website: <a href="https://ntruprime.cr.yp.to/">NTRU-Prime Website</a></description></item>.
/// </list>
/// </remarks>
class NTRUPrime final : public IAsymmetricCipher
{
private:

	const size_t SECRET_SIZE = 32;
	class NtruState;
	std::unique_ptr<NtruState> m_ntruState;
	std::unique_ptr<AsymmetricKey> m_privateKey;
	std::unique_ptr<AsymmetricKey> m_publicKey;
	std::unique_ptr<IPrng> m_rndGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	NTRUPrime(const NTRUPrime&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	NTRUPrime& operator=(const NTRUPrime&) = delete;

	/// <summary>
	/// Instantiate the cipher with auto-initialized prng and digest functions
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="PrngType">The seed prng function type; the default is the BCR generator</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng type, or parameter set is specified</exception>
	NTRUPrime(NTRUParameters Parameters = NTRUParameters::NTRUS2SQ4591N761, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using external Prng and Digest instances
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Prng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	NTRUPrime(NTRUParameters Parameters, IPrng* Prng);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~NTRUPrime();

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
	const NTRUParameters Parameters();

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
	bool Decapsulate(const std::vector<byte> &CipherText, std::vector<byte> &SharedSecret) override;

	/// <summary>
	/// Generate a shared secret and ciphertext.
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

	void CXOF(const std::vector<byte> &Domain, const std::vector<byte> &Key, std::vector<byte> &Secret, size_t Rate);
};

NAMESPACE_NTRUPRIMEEND
#endif
