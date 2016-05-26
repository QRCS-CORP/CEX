#ifndef _CEXENGINE_CIPHERMODEFROMNAME_H
#define _CEXENGINE_CIPHERMODEFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "ICipherMode.h"

NAMESPACE_HELPER

/// <summary>
/// CipherModeFromName: Get a Cipher Mode instance from it's enumeration name.
/// </summary>
class CipherModeFromName
{
public:
	/// <summary>
	/// Get an Cipher Mode instance by name using default parameters
	/// </summary>
	/// 
	/// <param name="CipherType">The cipher mode enumeration name</param>
	/// <param name="Engine">The block cipher instance</param>
	/// 
	/// <returns>An initialized digest</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Cipher::Symmetric::Block::Mode::ICipherMode* GetInstance(CEX::Enumeration::CipherModes CipherType, CEX::Cipher::Symmetric::Block::IBlockCipher* Engine);
};

NAMESPACE_HELPEREND
#endif