#ifndef CEX_AEADMODEFROMNAME_H
#define CEX_AEADMODEFROMNAME_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "BlockCipherExtensions.h"
#include "CryptoException.h"
#include "IAeadMode.h"

NAMESPACE_HELPER

using Enumeration::AeadModes;
using Enumeration::BlockCiphers;
using Enumeration::BlockCipherExtensions;
using Exception::CryptoException;
using Cipher::Block::IBlockCipher;
using Cipher::Block::Mode::IAeadMode;

/// <summary>
/// Get a Cipher Mode instance from it's enumeration name.
/// <para>The Cipher modes Initialize function must be called before it can be used.</para>
/// </summary>
class AeadModeFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Get an uninitialized AEAD mode instance by name
	/// </summary>
	/// 
	/// <param name="CipherType">The block-cipher enumeration name</param>
	/// <param name="CipherModeType">The AEAD cipher-mode enumeration name</param>
	/// 
	/// <returns>An uninitialized AEAD block-cipher mode instance</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the cipher, extension or mode types are not supported</exception>
	static IAeadMode* GetInstance(BlockCiphers CipherType, AeadModes CipherModeType);

	/// <summary>
	/// Get an uninitialized AEAD mode instance by name and a block-cipher pointer
	/// </summary>
	/// 
	/// <param name="Cipher">The block-cipher instance</param>
	/// <param name="CipherModeType">The AEAD cipher-mode enumeration name</param>
	/// 
	/// <returns>An uninitialized AEAD block-cipher mode instance</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the cipher is null or AEAD mode is not supported</exception>
	static IAeadMode* GetInstance(IBlockCipher* Cipher, AeadModes CipherModeType);
};

NAMESPACE_HELPEREND
#endif
