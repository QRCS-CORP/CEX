#ifndef CEX_BLOCKCIPHERFROMNAME_H
#define CEX_BLOCKCIPHERFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IBlockCipher.h"
#include "BlockCipherExtensions.h"

NAMESPACE_HELPER

using Enumeration::BlockCipherExtensions;
using Enumeration::BlockCiphers;
using Exception::CryptoException;
using Cipher::Symmetric::Block::IBlockCipher;

/// <summary>
/// Get a Block Cipher instance from it's enumeration name.
/// </summary>
class BlockCipherFromName
{
public:

	/// <summary>
	/// Get a symmetric block cipher instance.
	/// <para>If an extended (AHX/RHX, SHX, or THX) block cipher type is selected, the default key-schedule hash engine is None which involes the standard cipher.</para>
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// <param name="CipherExtensionType">The extended HX ciphers key schedule KDF</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IBlockCipher* GetInstance(BlockCiphers CipherType, BlockCipherExtensions CipherExtension = BlockCipherExtensions::None);
};

NAMESPACE_HELPEREND
#endif
