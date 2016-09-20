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
	/// Get a symmetric block cipher instance
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The block cipher enumeration name</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Cipher::Symmetric::Block::IBlockCipher* BlockCipherFromName::GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType);

	/// <summary>
	/// Get a symmetric block cipher instance with initialization parameters
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The symmetric block ciphers enumeration type name</param>
	/// <param name="BlockSize">The symmetric ciphers internal block size; 16 bytes with Twofish and Serpent, or 16/32 for Rijndael</param>
	/// <param name="RoundCount">The symmetric ciphers diffusion rounds count; requires KdfEngineType set to a supported digest type</param>
	/// <param name="KdfEngineType">The symmetric ciphers HKDF key expansion digest engine type; set to None for standard key schedule, select a digest for secure key expansion mode</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static CEX::Cipher::Symmetric::Block::IBlockCipher* GetInstance(CEX::Enumeration::BlockCiphers BlockCipherType, uint BlockSize, uint RoundCount, CEX::Enumeration::Digests KdfEngineType);
};

NAMESPACE_HELPEREND
#endif