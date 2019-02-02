#ifndef CEX_BLOCKCIPHERS_H
#define CEX_BLOCKCIPHERS_H

#include "CexDomain.h"
#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric block cipher enumeration names
/// <para>Note: HX ciphers are always ordinally higher in value than standard ciphers.</para>
/// </summary>
enum class BlockCiphers : byte
{
	/// <summary>
	/// No block cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An implementation of the AES Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	AES = static_cast<byte>(SymmetricCiphers::AES),
	/// <summary>
	/// An implementation of the Serpent Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	Serpent = static_cast<byte>(SymmetricCiphers::Serpent),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH256 = static_cast<byte>(SymmetricCiphers::RHXH256),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH512 = static_cast<byte>(SymmetricCiphers::RHXH512),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS256 = static_cast<byte>(SymmetricCiphers::RHXS256),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS512 = static_cast<byte>(SymmetricCiphers::RHXS512),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-1024 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS1024 = static_cast<byte>(SymmetricCiphers::RHXS1024),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH256 = static_cast<byte>(SymmetricCiphers::SHXH256),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH512 = static_cast<byte>(SymmetricCiphers::SHXH512),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS256 = static_cast<byte>(SymmetricCiphers::SHXS256),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS512 = static_cast<byte>(SymmetricCiphers::SHXS512),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-1024 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS1024 = static_cast<byte>(SymmetricCiphers::SHXS1024)
};

class BlockCipherConvert
{
public:

	/// <summary>
	/// Derive the BlockCiphers formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The BlockCiphers enumeration member</param>
	///
	/// <returns>The matching BlockCiphers string name</returns>
	static std::string ToName(BlockCiphers Enumeral);

	/// <summary>
	/// Derive the BlockCiphers enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The BlockCiphers string name</param>
	///
	/// <returns>The matching BlockCiphers enumeration type name</returns>
	static BlockCiphers FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif

