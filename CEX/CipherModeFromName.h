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
using Cipher::Symmetric::Block::IBlockCipher;
using Cipher::Symmetric::Block::Mode::ICipherMode;

/// <summary>
/// Get a Cipher Mode instance from it's enumeration name.
/// <para>The Cipher modes Initialize function must be called before it can be used.</para>
/// </summary>
class CipherModeFromName
{
public:

	/// <summary>
	/// Get an Cipher Mode instance by name using default parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// <param name="CipherExtensionType">The extended HX ciphers key schedule KDF</param>
	/// <param name="CipherModeType">The cipher mode enumeration name</param>
	/// 
	/// <returns>An uninitialized block cipher mode instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static ICipherMode* GetInstance(BlockCiphers CipherType, BlockCipherExtensions CipherExtensionType, CipherModes CipherModeType);

	/// <summary>
	/// Get a Cipher Mode instance by name with a block cipher instance
	/// </summary>
	/// 
	/// <param name="Cipher">The block cipher instance</param>
	/// <param name="CipherModeType">The cipher mode enumeration name</param>
	/// 
	/// <returns>An uninitialized block cipher mode instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static ICipherMode* GetInstance(IBlockCipher* Cipher, CipherModes CipherModeType);
};

NAMESPACE_HELPEREND
#endif
