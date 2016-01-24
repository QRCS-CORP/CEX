#ifndef _CEXENGINE_CIPHERMODEFROMNAME_H
#define _CEXENGINE_CIPHERMODEFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IBlockCipher.h"
#include "ICipherMode.h"
#include "CipherModes.h"

NAMESPACE_HELPER

using CEX::Cipher::Symmetric::Block::IBlockCipher;
using CEX::Cipher::Symmetric::Block::Mode::ICipherMode;
using CEX::Enumeration::CipherModes;
using CEX::Exception::CryptoException;

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
	/// <exception cref="CryptoException">Thrown if the enumeration name is not supported</exception>
	static ICipherMode* GetInstance(CipherModes CipherType, IBlockCipher* Engine);
};

NAMESPACE_HELPEREND
#endif