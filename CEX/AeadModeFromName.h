#ifndef CEX_AEADMODEFROMNAME_H
#define CEX_AEADMODEFROMNAME_H

#include "CexDomain.h"
#include "BlockCiphers.h"
#include "CryptoException.h"
#include "IAeadMode.h"

NAMESPACE_HELPER

using Enumeration::AeadModes;
using Enumeration::BlockCiphers;
using Exception::CryptoException;
using Cipher::Symmetric::Block::IBlockCipher;
using Cipher::Symmetric::Block::Mode::IAeadMode;

/// <summary>
/// Get a Cipher Mode instance from it's enumeration name.
/// <para>The Cipher modes Initialize function must be called before it can be used.</para>
/// </summary>
class AeadModeFromName
{
public:

	/// <summary>
	/// Get an Cipher Mode instance by name using default parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The AEAD cipher mode enumeration name</param>
	/// <param name="EngineType">The block cipher enumeration name</param>
	/// 
	/// <returns>A block cipher mode instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IAeadMode* GetInstance(AeadModes CipherType, BlockCiphers EngineType);

	/// <summary>
	/// Get an Cipher Mode instance by name using default parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The AEAD cipher mode enumeration name</param>
	/// <param name="Engine">The block cipher instance</param>
	/// 
	/// <returns>A block cipher mode instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IAeadMode* GetInstance(AeadModes CipherType, IBlockCipher* Engine);
};

NAMESPACE_HELPEREND
#endif
