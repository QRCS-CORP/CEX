#ifndef CEX_SYMMETRICENGINES_H
#define CEX_SYMMETRICENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric encryption ciphers enumeration names
/// </summary>
enum class SymmetricCiphers : byte
{
	/// <summary>
	/// No symmetric cipher is specified
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
	SHXS1024 = 49,
	/// <summary>
	/// The Authenticated Stream Cipher; using AHX-KMAC256
	/// </summary>
	ACS256A = 64,
	/// <summary>
	/// The Authenticated Stream Cipher; using AHX-KMAC512
	/// </summary>
	ACS512A = 65,
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC256
	/// </summary>
	ACS256S = 66,
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC512
	/// </summary>
	ACS512S = 67,
	/// <summary>
	/// The Authenticated Stream Cipher; using default parameters AHX-CSHAKE512-KMAC512
	/// </summary>
	ACS = 68,
	/// <summary>
	/// The ChaChaPoly20 stream cipher
	/// </summary>
	ChaCha256 = 96,
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with KMAC256
	/// </summary>
	ChaCha256AE = 97,
	/// <summary>
	/// The ChaChaPoly80 stream cipher
	/// </summary>
	ChaCha512 = 98,
	/// <summary>
	/// The ChaChaPoly80 stream cipher authenticated with KMAC512
	/// </summary>
	ChaCha512AE = 99,
	/// <summary>
	/// The Threefish 256-bit stream cipher
	/// </summary>
	Threefish256 = 128,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC256
	/// </summary>
	Threefish256AE = 129,
	/// <summary>
	/// The Threefish 512-bit stream cipher
	/// </summary>
	Threefish512 = 130,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC512
	/// </summary>
	Threefish512AE = 131,
	/// <summary>
	/// The Threefish 1024-bit stream cipher
	/// </summary>
	Threefish1024 = 132,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC1024
	/// </summary>
	Threefish1024AE = 133
};

NAMESPACE_ENUMERATIONEND
#endif
