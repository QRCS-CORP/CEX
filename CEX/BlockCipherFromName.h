#ifndef CEX_BLOCKCIPHERFROMNAME_H
#define CEX_BLOCKCIPHERFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IBlockCipher.h"

NAMESPACE_HELPER

using Enumeration::BlockCiphers;
using Exception::CryptoException;
using Cipher::Block::IBlockCipher;

/// <summary>
/// Get a Block Cipher instance from it's enumeration name.
/// </summary>
class BlockCipherFromName
{
private:

	static const std::string CLASS_NAME;

public:

	/// <summary>
	/// Get a symmetric block cipher instance by it's enumeration name.
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="CryptoException">Thrown if the block cipher type is not supported</exception>
	static IBlockCipher* GetInstance(BlockCiphers CipherType);
};

NAMESPACE_HELPEREND
#endif
