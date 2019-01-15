#ifndef CEX_STREAMCIPHERS_H
#define CEX_STREAMCIPHERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Stream cipher enumeration names
/// </summary>
enum class StreamCiphers : byte
{
	/// <summary>
	/// No stream cipher is specified
	/// </summary>
	None = 0,
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
