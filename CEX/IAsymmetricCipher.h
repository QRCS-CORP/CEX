#ifndef CEX_IASYMMETRICCIPHER_H
#define CEX_IASYMMETRICCIPHER_H

#include "CexDomain.h"
#include "CryptoAsymmetricException.h"
#include "Digests.h"
#include "IAsymmetricKey.h"
#include "IAsymmetricKeyPair.h"
#include "IDigest.h"
#include "IPrng.h"
#include "Prngs.h"

NAMESPACE_ASYMMETRIC

using Enumeration::AsymmetricEngines;
using Exception::CryptoAsymmetricException;
using Key::Asymmetric::IAsymmetricKey;
using Key::Asymmetric::IAsymmetricKeyPair;
using Digest::IDigest;
using Enumeration::Digests;
using Prng::IPrng;
using Enumeration::Prngs;

/// <summary>
/// The Asymmetric cipher interface
/// </summary>
class IAsymmetricCipher
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	IAsymmetricCipher() {}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~IAsymmetricCipher() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The cipher type-name
	/// </summary>
	virtual const AsymmetricEngines Enumeral() = 0;

	/// <summary>
	/// Get: The cipher is initialized for encryption
	/// </summary>
	virtual const bool IsEncryption() = 0;

	/// <summary>
	/// Get: The cipher has been initialized with a key
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get: The ciphers name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Get/Set: A new asymmetric key-pairs optional identification tag.
	/// <para>Setting this value must be done before the Generate method is called.</para>
	/// </summary>
	virtual std::vector<byte> &Tag() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Decrypt an encrypted cipher-text and return the shared secret
	/// </summary>
	/// 
	/// <param name="CipherText">The input cipher-text</param>
	virtual std::vector<byte> Decrypt(std::vector<byte> &CipherText) = 0;

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Encrypt a shared secret and return the encrypted message
	/// </summary>
	/// 
	/// <param name="Message">The shared secret array</param>
	virtual std::vector<byte> Encrypt(std::vector<byte> &Message) = 0;

	/// <summary>
	/// Generate a public/private key-pair
	/// </summary>
	virtual IAsymmetricKeyPair* Generate() = 0;

	/// <summary>
	/// Initialize the cipher for encryption or decryption
	/// </summary>
	/// 
	/// <param name="Encryption">Initialize the cipher for encryption or decryption</param>
	/// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the Public (encrypt) and/or Private (decryption) key</param>
	virtual void Initialize(bool Encryption, IAsymmetricKeyPair* KeyPair) = 0;
};

NAMESPACE_ASYMMETRICEND
#endif

