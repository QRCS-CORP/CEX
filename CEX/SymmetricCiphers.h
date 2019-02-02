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
	/// An implementation of the AES Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	AES = 1,
	/// <summary>
	/// An implementation of the Serpent Block Cipher.
	/// <para>Standards based implementation: uses a 128-bit block and 128/192/256-bit key sizes.</para>
	/// </summary>
	Serpent = 2,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH256 = 39,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF(SHA512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXH512 = 40,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS256 = 41,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS512 = 42,
	/// <summary>
	/// An Rijndael implementation based on the 128-bit Rijndael Block Cipher extended with an cSHAKE-1024 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	RHXS1024 = 43,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA256) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH256 = 45,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an HKDF(SHA512) secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXH512 = 46,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-256 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS256 = 47,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-512 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS512 = 48,
	/// <summary>
	/// An implementation of the Serpent Block Cipher extended with an cSHAKE-1024 secure key schedule.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	SHXS1024 = 49,
	/// <summary>
	/// The Authenticated Stream Cipher; using RHX-KMAC256.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	ACS256A = 64,
	/// <summary>
	/// The Authenticated Stream Cipher; using RHX-KMAC512.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	ACS512A = 65,
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC256.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	ACS256S = 66,
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC512.
	/// <para>Extended cipher implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	ACS512S = 67,
	/// <summary>
	/// The Authenticated Stream Cipher; using default parameters AES-CSHAKE512-KMAC512.
	/// <para>Standards based implementation: uses a 128-bit block and 256/512/1024-bit key sizes.</para>
	/// </summary>
	ACS = 68,
	/// <summary>
	/// An standard implementation of the ChaChaPoly20 stream cipher.
	/// <para>Standards based implementation: uses a 512-bit block a 256-bit key size</para>
	/// </summary>
	ChaCha256 = 96,
	/// <summary>
	/// The ChaChaPoly20 stream cipher authenticated with KMAC256
	/// <para>Extended cipher implementation: uses a 512-bit block a 256-bit key size</para>
	/// </summary>
	ChaCha256AE = 97,
	/// <summary>
	/// The ChaChaPoly80 stream cipher.
	/// <para>Extended cipher implementation: uses a 512-bit block a 512-bit key size</para>
	/// </summary>
	ChaCha512 = 98,
	/// <summary>.
	/// The ChaChaPoly80 stream cipher authenticated with KMAC512.
	/// <para>Extended cipher implementation: uses a 512-bit block a 512-bit key size</para>
	/// </summary>
	ChaCha512AE = 99,
	/// <summary>
	/// The Threefish 256-bit stream cipher.
	/// <para>Standards based implementation: uses a 256-bit block a 256-bit key size</para>
	/// </summary>
	Threefish256 = 128,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC256.
	/// <para>Extended cipher implementation: uses a 256-bit block a 256-bit key size</para>
	/// </summary>
	Threefish256AE = 129,
	/// <summary>
	/// The Threefish 512-bit stream cipher.
	/// <para>Extended cipher implementation: uses a 512-bit block a 512-bit key size</para>
	/// </summary>
	Threefish512 = 130,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC512.
	/// <para>Extended cipher implementation: uses a 512-bit block a 512-bit key size</para>
	/// </summary>
	Threefish512AE = 131,
	/// <summary>
	/// The Threefish 1024-bit stream cipher.
	/// <para>Extended cipher implementation: uses a 1024-bit block a 1024-bit key size</para>
	/// </summary>
	Threefish1024 = 132,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC1024.
	// <para>Extended cipher implementation: uses a 1024-bit block a 1024-bit key size</para>
	/// </summary>
	Threefish1024AE = 133
};

class SymmetricCipherConvert
{
public:

	/// <summary>
	/// Derive the SymmetricCiphers formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The SymmetricCiphers enumeration member</param>
	///
	/// <returns>The matching SymmetricCiphers string name</returns>
	static std::string ToName(SymmetricCiphers Enumeral);

	/// <summary>
	/// Derive the SymmetricCiphers enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The SymmetricCiphers string name</param>
	///
	/// <returns>The matching SymmetricCiphers enumeration type name</returns>
	static SymmetricCiphers FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
