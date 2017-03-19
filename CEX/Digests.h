#ifndef _CEX_DIGESTS_H
#define _CEX_DIGESTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Cryptographic hash functions enmumeration names
/// </summary>
enum class Digests : byte
{
	/// <summary>
	/// No hash digest is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Blake256Compress digest with a 256 bit return size
	/// </summary>
	Blake256 = 1,
	/// <summary>
	/// The Blake512Compress digest with a 512 bit return size
	/// </summary>
	Blake512 = 2,
	/// <summary>
	/// The SHA-3 digest based on Keccak with a 256 bit return size
	/// </summary>
	Keccak256 = 3,
	/// <summary>
	/// The SHA-3 digest based on Keccak with a 512 bit return size
	/// </summary>
	Keccak512 = 4,
	/// <summary>
	///The SHA-2 digest with a 256 bit return size
	/// </summary>
	SHA256 = 5,
	/// <summary>
	/// The SHA-2 digest with a 512 bit return size
	/// </summary>
	SHA512 = 6,
	/// <summary>
	/// The Skein digest with a 256 bit return size
	/// </summary>
	Skein256 = 7,
	/// <summary>
	/// The Skein digest with a 512 bit return size
	/// </summary>
	Skein512 = 8,
	/// <summary>
	/// The Skein digest with a 1024 bit return size
	/// </summary>
	Skein1024 = 9
};

NAMESPACE_ENUMERATIONEND
#endif