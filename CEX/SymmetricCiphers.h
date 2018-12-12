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
	/// An implementation based on the Rijndael Block Cipher
	/// </summary>
	Rijndael = 1,
	/// <summary>
	/// An implementation based on the Serpent Block Cipher
	/// </summary>
	Serpent = 2,
	/// <summary>
	/// An implementation based on the Twofish Block Cipher
	/// </summary>
	Twofish = 3,
	/// <summary>
	/// An AES-NI implementation based on the 128-bit Rijndael Block Cipher extended with an HKDF key schedule
	/// </summary>
	AHX = 32,
	/// <summary>
	/// An implementation based on the Rijndael Block Cipher extended with an HKDF key schedule
	/// </summary>
	RHX = 33,
	/// <summary>
	/// An implementation based on the Serpent Block Cipher extended with an HKDF key schedule
	/// </summary>
	SHX = 34,
	/// <summary>
	/// The Authenticated Stream Cipher; using AHX-KMAC256
	/// </summary>
	ACS256A = 59,
	/// <summary>
	/// The Authenticated Stream Cipher; using AHX-KMAC512
	/// </summary>
	ACS512A = 60,
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC256
	/// </summary>
	ACS256S = 61,
	/// <summary>
	/// The Authenticated Stream Cipher; using SHX-KMAC512
	/// </summary>
	ACS512S = 62,
	/// <summary>
	/// The Authenticated Stream Cipher; using default parameters AHX-CSHAKE512-KMAC512
	/// </summary>
	ACS = 63,
	/// <summary>
	/// The ChaChaPoly20 stream cipher
	/// </summary>
	ChaCha256 = 64,
	/// <summary>
	/// The ChaChaPoly80 stream cipher
	/// </summary>
	ChaCha512 = 65,
	/// <summary>
	/// The Threefish 256-bit stream cipher
	/// </summary>
	Threefish256 = 66,
	/// <summary>
	/// The Threefish 512-bit stream cipher
	/// </summary>
	Threefish512 = 67,
	/// <summary>
	/// The Threefish 1024-bit stream cipher
	/// </summary>
	Threefish1024 = 68
};

NAMESPACE_ENUMERATIONEND
#endif
