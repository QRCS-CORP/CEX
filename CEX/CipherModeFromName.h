#ifndef CEX_CIPHERMODEFROMNAME_H
#define CEX_CIPHERMODEFROMNAME_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "CryptoException.h"
#include "ICipherMode.h"

NAMESPACE_HELPER

using Enumeration::BlockCiphers;
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
	/// <param name="CipherType">The cipher mode enumeration name</param>
	/// <param name="EngineType">The block cipher enumeration name</param>
	/// 
	/// <returns>A block cipher mode instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static ICipherMode* GetInstance(CipherModes CipherType, BlockCiphers EngineType);

	/// <summary>
	/// Get an Cipher Mode instance by name using default parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The cipher mode enumeration name</param>
	/// <param name="Engine">The block cipher instance</param>
	/// 
	/// <returns>A block cipher mode instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static ICipherMode* GetInstance(CipherModes CipherType, IBlockCipher* Engine);
};

NAMESPACE_HELPEREND
#endif