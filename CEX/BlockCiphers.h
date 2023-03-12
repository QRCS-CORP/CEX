#ifndef CEX_BLOCKCIPHERS_H
#define CEX_BLOCKCIPHERS_H

#include "CexDomain.h"
#include "SymmetricCiphers.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric block cipher enumeration names
/// <para>Note: HX ciphers are always ordinally higher in value than standard ciphers.</para>
/// </summary>
enum class BlockCiphers : uint8_t
{
	/// <summary>
	/// No block cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An implementation of the AES Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	AES = static_cast<uint8_t>(SymmetricCiphers::AES),
	/// <summary>
	/// An implementation of the Serpent Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	Serpent = static_cast<uint8_t>(SymmetricCiphers::Serpent),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA2256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH256 = static_cast<uint8_t>(SymmetricCiphers::RHXH256),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA2512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH512 = static_cast<uint8_t>(SymmetricCiphers::RHXH512),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS256 = static_cast<uint8_t>(SymmetricCiphers::RHXS256),
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS512 = static_cast<uint8_t>(SymmetricCiphers::RHXS512),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA2256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH256 = static_cast<uint8_t>(SymmetricCiphers::SHXH256),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA2512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH512 = static_cast<uint8_t>(SymmetricCiphers::SHXH512),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS256 = static_cast<uint8_t>(SymmetricCiphers::SHXS256),
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS512 = static_cast<uint8_t>(SymmetricCiphers::SHXS512)
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

