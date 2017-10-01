#ifndef CEX_BLOCKCIPHERFROMNAME_H
#define CEX_BLOCKCIPHERFROMNAME_H

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
	/// <para>If an extended (AHX/RHX, SHX, or THX) block cipher type is selected, the default key-schedule hash engine is SHA2-256.
	/// Selecting a root cipher type (Rijndael, Serpent, or Twofish), will return a standard cipher configuration.</para>
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The block cipher enumeration name</param>
	/// <param name="KdfEngineType">The [optional] (HX) extended ciphers HKDF hash engine; the default is SHA256.</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IBlockCipher* BlockCipherFromName::GetInstance(BlockCiphers BlockCipherType, Digests KdfEngineType = Digests::SHA256);

	/// <summary>
	/// Get a symmetric block cipher instance with initialization parameters.
	/// <para>Selecting a root cipher type (Rijndael, Serpent, or Twofish), will return a standard cipher configuration.</para>
	/// </summary>
	/// 
	/// <param name="BlockCipherType">The symmetric block ciphers enumeration type name</param>
	/// <param name="RoundCount">The symmetric ciphers transformation rounds count; requires KdfEngineType set to a supported digest type</param>
	/// <param name="KdfEngineType">The extended (HX) ciphers HKDF key expansion digest engine type; set to None for standard key schedule, select a digest for secure key expansion mode</param>
	/// 
	/// <returns>A symmetric block cipher instance</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IBlockCipher* GetInstance(BlockCiphers BlockCipherType, Digests KdfEngineType, uint RoundCount);
};

NAMESPACE_HELPEREND
#endif