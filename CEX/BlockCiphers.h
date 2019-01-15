#ifndef CEX_BLOCKCIPHERS_H
#define CEX_BLOCKCIPHERS_H

#include "CexDomain.h"

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
	/// An implementation of the Rijndael Block Cipher
	/// </summary>
	Rijndael = 1,
	/// <summary>
	/// An implementation of the Serpent Block Cipher
	/// </summary>
	Serpent = 2,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher
	/// </summary>
	AHX = 32,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA256) secure key schedule
	/// </summary>
	AHXH256 = 33,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA512) secure key schedule
	/// </summary>
	AHXH512 = 34,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-256 secure key schedule
	/// </summary>
	AHXS256 = 35,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-512 secure key schedule
	/// </summary>
	AHXS512 = 36,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-1024 secure key schedule
	/// </summary>
	AHXS1024 = 37,
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher
	/// </summary>
	RHX = 38,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA256) secure key schedule
	/// </summary>
	RHXH256 = 39,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA512) secure key schedule
	/// </summary>
	RHXH512 = 40,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-256 secure key schedule
	/// </summary>
	RHXS256 = 41,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-512 secure key schedule
	/// </summary>
	RHXS512 = 42,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-1024 secure key schedule
	/// </summary>
	RHXS1024 = 43,
	/// <summary>
	/// An implementation of the Serpent Block Cipher
	/// </summary>
	SHX = 44,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA256) secure key schedule
	/// </summary>
	SHXH256 = 45,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA512) secure key schedule
	/// </summary>
	SHXH512 = 46,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-256 secure key schedule
	/// </summary>
	SHXS256 = 47,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-512 secure key schedule
	/// </summary>
	SHXS512 = 48,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-1024 secure key schedule
	/// </summary>
	SHXS1024 = 49
};

NAMESPACE_ENUMERATIONEND
#endif

