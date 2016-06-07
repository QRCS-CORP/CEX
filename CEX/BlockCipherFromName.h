#ifndef _CEXENGINE_BLOCKCIPHERFROMNAME_H
#define _CEXENGINE_BLOCKCIPHERFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IBlockCipher.h"

NAMESPACE_HELPER

/// <summary>
/// BlockCipherFromName: Get a Block Cipher instance from it's enumeration name.
/// </summary>
class BlockCipherFromName
{
public:
	/// <summary>
	/// Get a block cipher instance with default initialization parameters
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The block cipher enumeration name</param>
	/// 
	/// <returns>An initialized block cipher</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Cipher::Symmetric::Block::IBlockCipher* BlockCipherFromName::GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType);

	/// <summary>
	/// Get a block cipher instance with specified initialization parameters
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The block cipher enumeration name</param>
	/// <param name="BlockSize">The cipher block size</param>
	/// <param name="RoundCount">The number of cipher rounds</param>
	/// <param name="KdfEngineType">The ciphers key expansion engine (HX ciphers)</param>
	/// 
	/// <returns>An initialized block cipher</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Cipher::Symmetric::Block::IBlockCipher* GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType, uint BlockSize, uint RoundCount, CEX::Enumeration::Digests KdfEngineType);
};

NAMESPACE_HELPEREND
#endif