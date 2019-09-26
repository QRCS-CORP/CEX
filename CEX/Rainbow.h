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
//
// Updated by September 24, 2019
// Contact: develop@vtdev.com

#ifndef CEX_RAINBOW_H
#define CEX_RAINBOW_H

#include "AsymmetricKey.h"
#include "AsymmetricKeyPair.h"
#include "IAsymmetricSigner.h"
#include "RainbowParameters.h"

NAMESPACE_RAINBOW

using Enumeration::RainbowParameters;

/// <summary>
/// An implementation of the Rainbow asymmetric signature scheme (RAINBOW)
/// </summary> 
/// 
/// <example>
/// <description>Key generation:</description>
/// <code>
/// Rainbow sgn(RainbowParameters::RNBWS2S192SHAKE512);
/// IAsymmetricKeyPair* kp = sgn.Generate();
/// 
/// // serialize the public key
///	IAsymmetricKey* pubk = kp->PublicKey();
/// std::vector&lt;byte&gt; pk = pubk->ToBytes();
/// </code>
///
/// <description>Sign:</description>
/// <code>
/// Rainbow sgn(RainbowParameters::RNBWS2S192SHAKE512);
/// sgn.Initialize(PrivateKey);
/// 
/// std::vector&lt;byte&gt; msg(32);
/// std::vector&lt;byte&gt; sig(0);
/// // generate the signature
/// sgn.Sign(msg, sig);
/// </code>
///
/// <description>Verify:</description>
/// <code>
/// Rainbow sgn(RainbowParameters::RNBWS2S192SHAKE512);
/// sgn.Initialize(PublicKey);
/// std::vector&lt;byte&gt; message(0);
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
/// <description>Implementation Notes:</description>
/// <para>Rainbow is an asymmetric signature scheme based on multivariate polynomials over a finite field. \n
/// Signature sizes are small and vary by the the parameters; 127 bytes (S128), 156 bytes (S192), and 204 bytes with the strongest parameter S256. \n
/// Rainbow is designed to provide long-term security even against attackers equipped with quantum computers.</para>
/// 
/// <list type="bullet">
/// <item><description>There are three available parameters set through the constructor, ordered by security strength (S1, S2, S3); RNBWS1S128SHAKE256, RNBWS2S192SHAKE512, and RNBWS3S256SHAKE512 (strongest)</description></item>
/// <item><description>The signature schemes operational mode (signing/verifying) is determined by the IAsymmetricKey key-type used to Initialize the cipher (AsymmetricKeyTypes: CipherPublicKey, or CipherPublicKey), Public for encryption, Private for Decryption.</description></item>
/// <item><description>The primary Prng is set through the constructor, as either an prng type-name (default BCR-AES256), which instantiates the function internally, or a pointer to a perisitant external instance of a Prng</description></item>
/// <item><description>Use the Generate function to create a public/private key-pair, and the Sign function to sign a message</description></item>
/// <item><description>The message-signature is tested using the Verify function, which checks the signature, populates the message array, and returns false on authentication failure</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST Rainbow <a href="https://csrc.nist.gov/CSRC/media/Presentations/rainbow-round-2-presentation/images-media/rainbow-ding.pdf">Presentation</a> .</description></item>
/// <item><description>NIST Post Quantum Competition <a href="https://csrc.nist.gov/projects/post-quantum-cryptography/round-2-submissions">Round 2</a>.</description></item>
/// </list>
/// </remarks>
class Rainbow final : public IAsymmetricSigner
{
private:

	class RainbowState;
	std::unique_ptr<RainbowState> m_rainbowState;
	std::unique_ptr<AsymmetricKey> m_privateKey;
	std::unique_ptr<AsymmetricKey> m_publicKey;
	std::unique_ptr<IPrng> m_rndGenerator;

public:

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	Rainbow(const Rainbow&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	Rainbow& operator=(const Rainbow&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	/// 
	/// <param name="Parameters">The SPHINCS+ parameter set; default is SPXPS2S192SHAKE</param>
	/// <param name="PrngType">The random prng provider; default is Block-cipher Counter Rng (BCR)</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	Rainbow(RainbowParameters Parameters = RainbowParameters::RNBWS2S192SHAKE512, Prngs PrngType = Prngs::BCR);

	/// <summary>
	/// Constructor: instantiate this class using an external Prng instance
	/// </summary>
	///
	/// <param name="Parameters">The parameter set enumeration name</param>
	/// <param name="Rng">A pointer to the seed Prng function</param>
	/// 
	/// <exception cref="CryptoAsymmetricException">Thrown if an invalid prng, or parameter set is specified</exception>
	Rainbow(RainbowParameters Parameters, IPrng* Rng);

	/// <summary>
	/// Finalizer: destroys the containers objects
	/// </summary>
	virtual ~Rainbow() noexcept;

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
	/// Read Only: The signature scheme name, including the loaded parameter-set
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read Only: The Private key-size in bytes
	/// </summary>
	const size_t PrivateKeySize() override;

	/// <summary>
	/// Read Only: The Public key size in bytes
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
	/// <returns>A public/private key pair</returns>
	AsymmetricKeyPair* Generate() override;

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
	/// <param name="Message">The message byte array containing the message to sign</param>
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
	/// <returns>Returns true if the signature matches, false for authentication failure</returns>
	bool Verify(const std::vector<byte> &Signature, std::vector<byte> &Message) override;
};

NAMESPACE_RAINBOWEND
#endif

