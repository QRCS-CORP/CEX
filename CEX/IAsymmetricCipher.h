#ifndef _CEX_IASYMMETRICCIPHER_H
#define _CEX_IASYMMETRICCIPHER_H

#include "CexDomain.h"
#include "CryptoAsymmetricException.h"
#include "IAsymmetricKey.h"
#include "IAsymmetricKeyPair.h"

NAMESPACE_ASYMMETRICENCRYPT

using Enumeration::AsymmetricEngines;
using Exception::CryptoAsymmetricException;
using Key::Asymmetric::IAsymmetricKey;
using Key::Asymmetric::IAsymmetricKeyPair;

/// <summary>
/// The Asymmetric cipher interface
/// </summary>
class IAsymmetricCipher
{
public:

	IAsymmetricCipher(const IAsymmetricCipher&) = delete;
	IAsymmetricCipher& operator=(const IAsymmetricCipher&) = delete;

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
	/// Get: The maximum number of bytes the cipher can encrypt or decrypt
	/// </summary>
	virtual const size_t MaxInputSize() = 0;

	/// <summary>
	/// Get: The ciphers name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the cipher for encryption or decryption
	/// </summary>
	/// 
	/// <param name="Encryption">Initialize the cipher for encryption or decryption</param>
	/// <param name="KeyPair">The <see cref="IAsymmetricKeyPair"/> containing the Public (encrypt) and/or Private (decryption) key</param>
	virtual const void Initialize(bool Encryption, IAsymmetricKeyPair &KeyPair) = 0;

	/// <summary>
	/// Decrypt an encrypted cipher-text
	/// </summary>
	/// 
	/// <param name="Input">The input cipher-text</param>
	/// <param name="InOffset">The starting position within the input array</param>
	/// <param name="Output">The output plain-text</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	virtual const void Decrypt(std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Encrypt a plain-text message
	/// </summary>
	/// 
	/// <param name="Input">The input plain-text</param>
	/// <param name="InOffset">The starting position within the input array</param>
	/// <param name="Output">The output cipher-text</param>
	/// <param name="OutOffset">The starting position within the output array</param>
	virtual const void Encrypt(std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Generate an encryption key-pair
	/// </summary>
	/// 
	/// <param name="KeyPair">An asymmetric key-pair containing public and private keys</param>
	virtual const void Generate(IAsymmetricKeyPair &KeyPair) = 0;
};

NAMESPACE_ASYMMETRICENCRYPTEND
#endif

