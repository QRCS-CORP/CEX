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
