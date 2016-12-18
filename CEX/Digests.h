#ifndef _CEX_DIGESTS_H
#define _CEX_DIGESTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Cryptographic hash functions enmumeration names
/// </summary>
enum class Digests : uint8_t
{
	/// <summary>
	/// No hash digest is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Blake2B digest with a 512 bit return size
	/// </summary>
	BlakeB512 = 1,
	/// <summary>
	/// The parallelized Blake2BP digest with a 512 bit return size
	/// </summary>
	BlakeBP512 = 2,
	/// <summary>
	/// The Blake2S digest with a 256 bit return size
	/// </summary>
	BlakeS256 = 3,
	/// <summary>
	/// The parallelized Blake2SP digest with a 256 bit return size
	/// </summary>
	BlakeSP256 = 4,
	/// <summary>
	/// The SHA-3 digest based on Keccak with a 256 bit return size
	/// </summary>
	Keccak256 = 7,
	/// <summary>
	/// The SHA-3 digest based on Keccak with a 512 bit return size
	/// </summary>
	Keccak512 = 8,
	/// <summary>
	///The SHA-2 digest with a 256 bit return size
	/// </summary>
	SHA256 = 9,
	/// <summary>
	/// The SHA-2 digest with a 512 bit return size
	/// </summary>
	SHA512 = 10,
	/// <summary>
	/// The Skein digest with a 256 bit return size
	/// </summary>
	Skein256 = 11,
	/// <summary>
	/// The Skein digest with a 512 bit return size
	/// </summary>
	Skein512 = 12,
	/// <summary>
	/// The Skein digest with a 1024 bit return size
	/// </summary>
	Skein1024 = 13
};

NAMESPACE_ENUMERATIONEND
#endif