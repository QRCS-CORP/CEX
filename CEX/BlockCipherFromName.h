#ifndef _CEX_BLOCKCIPHERFROMNAME_H
#define _CEX_BLOCKCIPHERFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IBlockCipher.h"

NAMESPACE_HELPER

using Enumeration::BlockCiphers;
using Enumeration::Digests;
using Cipher::Symmetric::Block::IBlockCipher;

/// <summary>
/// Get a Block Cipher instance from it's enumeration name.
/// </summary>
class BlockCipherFromName
{
public:
	/// <summary>
	/// Get a symmetric block cipher instance.
	/// <para>If an extended (HX) block cipher type is selected, the default HKDF hash engine is SHA2-512.</para>
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The block cipher enumeration name</param>
	/// <param name="KdfEngineType">The [optional] (HX) extended ciphers HKDF digest engine; the default is None</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers BlockCipherType, Digests KdfEngineType = Digests::None);

	/// <summary>
	/// Get a symmetric block cipher instance with initialization parameters
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The symmetric block ciphers enumeration type name</param>
	/// <param name="BlockSize">The symmetric ciphers internal block size; 16 bytes with Twofish and Serpent, or 16/32 for Rijndael</param>
	/// <param name="RoundCount">The symmetric ciphers transformation rounds count; requires KdfEngineType set to a supported digest type</param>
	/// <param name="KdfEngineType">The extended (HX) ciphers HKDF key expansion digest engine type; set to None for standard key schedule, select a digest for secure key expansion mode</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IBlockCipher* GetInstance(BlockCiphers BlockCipherType, uint BlockSize, uint RoundCount, Digests KdfEngineType);
};

NAMESPACE_HELPEREND
#endif