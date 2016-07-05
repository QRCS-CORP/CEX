#ifndef _CEXENGINE_DIGESTS_H
#define _CEXENGINE_DIGESTS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Message Digests
/// </summary>
enum class Digests : uint
{
	/// <summary>
	/// No digest selected
	/// </summary>
	None = 0,
	/// <summary>
	/// The Blake2B digest with a 512 bit return size
	/// </summary>
	Blake2B512 = 1,
	/// <summary>
	/// The parallelized Blake2BP digest with a 512 bit return size
	/// </summary>
	Blake2BP512 = 2,
	/// <summary>
	/// The Blake2S digest with a 256 bit return size
	/// </summary>
	Blake2S256 = 3,
	/// <summary>
	/// The parallelized Blake2SP digest with a 256 bit return size
	/// </summary>
	Blake2SP256 = 4,
	/// <summary>
	/// The Blake digest with a 256 bit return size
	/// </summary>
	Blake256 = 5,
	/// <summary>
	/// The Blake digest with a 512 bit return size
	/// </summary>
	Blake512 = 6,
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