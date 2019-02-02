#ifndef CEX_CIPHERMODEFROMNAME_H
#define CEX_CIPHERMODEFROMNAME_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "BlockCipherExtensions.h"
#include "CryptoException.h"
#include "ICipherMode.h"

NAMESPACE_HELPER

using Enumeration::BlockCiphers;
using Enumeration::BlockCipherExtensions;
using Enumeration::CipherModes;
using Exception::CryptoException;
using Cipher::Block::IBlockCipher;
using Cipher::Block::Mode::ICipherMode;

/// <summary>
/// Get a Cipher Mode instance from it's enumeration name.
/// <para>The Cipher modes Initialize function must be called before it can be used.</para>
/// </summary>
class CipherModeFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Get an Cipher Mode instance by name using default parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// <param name="CipherModeType">The cipher mode enumeration name</param>
	/// 
	/// <returns>An uninitialized block cipher mode instance</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the block cipher, extension or mode are not supported</exception>
	static ICipherMode* GetInstance(BlockCiphers CipherType, CipherModes CipherModeType);

	/// <summary>
	/// Get a Cipher Mode instance by name with a block cipher instance
	/// </summary>
	/// 
	/// <param name="Cipher">The block cipher instance</param>
	/// <param name="CipherModeType">The cipher mode enumeration name</param>
	/// 
	/// <returns>An uninitialized block cipher mode instance</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the cipher is null or the mode is not supported</exception>
	static ICipherMode* GetInstance(IBlockCipher* Cipher, CipherModes CipherModeType);
};

NAMESPACE_HELPEREND
#endif
