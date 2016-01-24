#ifndef _CEXENGINE_BLOCKCIPHERFROMNAME_H
#define _CEXENGINE_BLOCKCIPHERFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IBlockCipher.h"
#include "Digests.h"
#include "BlockCiphers.h"

NAMESPACE_HELPER

using CEX::Cipher::Symmetric::Block::IBlockCipher;
using CEX::Enumeration::Digests;
using CEX::Enumeration::BlockCiphers;
using CEX::Exception::CryptoException;

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
	/// <param name="EngineType">The block cipher enumeration name</param>
	/// 
	/// <returns>An initialized block cipher</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the enumeration name is not supported</exception>
	static IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers EngineType);

	/// <summary>
	/// Get a block cipher instance with specified initialization parameters
	/// </summary>
	/// 
	/// <param name="EngineType">The block cipher enumeration name</param>
	/// <param name="BlockSize">The cipher block size</param>
	/// <param name="RoundCount">The number of cipher rounds</param>
	/// <param name="KdfEngine">The ciphers key expansion engine (HX ciphers)</param>
	/// 
	/// <returns>An initialized block cipher</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the enumeration name is not supported</exception>
	static IBlockCipher* GetInstance(BlockCiphers EngineType, int BlockSize, int RoundCount, Digests KdfEngine);
};

NAMESPACE_HELPEREND
#endif