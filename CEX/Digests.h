#ifndef CEX_DIGESTS_H
#define CEX_DIGESTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Cryptographic hash functions enumeration names
/// </summary>
enum class Digests : byte
{
	/// <summary>
	/// No hash digest is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Blake2S digest with a 256 bit return size
	/// </summary>
	Blake256 = 1,
	/// <summary>
	/// The Blake2B digest with a 512 bit return size
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
	/// The SHA-3 digest based on Keccak with a 1024 bit return size
	/// </summary>
	Keccak1024 = 5,
	/// <summary>
	///The SHA-2 digest with a 256 bit return size
	/// </summary>
	SHA256 = 6,
	/// <summary>
	/// The SHA-2 digest with a 512 bit return size
	/// </summary>
	SHA512 = 7,
	/// <summary>
	/// The SHAKE-128 digest with a 128 bit return size
	/// </summary>
	SHAKE128 = 8,
	/// <summary>
	/// The SHAKE-256 digest with a 256 bit return size
	/// </summary>
	SHAKE256 = 9,
	/// <summary>
	/// The SHAKE-512 digest with a 512 bit return size
	/// </summary>
	SHAKE512 = 10,
	/// <summary>
	/// The SHAKE-1024 digest with a 1024 bit return size
	/// </summary>
	SHAKE1024 = 11,
	/// <summary>
	/// The Skein digest with a 256 bit return size
	/// </summary>
	Skein256 = 12,
	/// <summary>
	/// The Skein digest with a 512 bit return size
	/// </summary>
	Skein512 = 13,
	/// <summary>
	/// The Skein digest with a 1024 bit return size
	/// </summary>
	Skein1024 = 14
};

NAMESPACE_ENUMERATIONEND
#endif
