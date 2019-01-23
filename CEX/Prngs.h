#ifndef CEX_PRNGS_H
#define CEX_PRNGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Pseudo Random Generators enumeration names
/// </summary>
enum class Prngs : byte
{
	/// <summary>
	/// No prng is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Symmetric Cipher Counter mode random number generator using AES
	/// </summary>
	BCR = 1,
	/// <summary>
	/// A Symmetric Cipher Counter mode random number generator using AHX/RHX and cSHAKE-256
	/// </summary>
	BCRAHXS256 = 2,
	/// <summary>
	/// A Symmetric Cipher Counter mode random number generator using AHX/RHX and cSHAKE-512
	/// </summary>
	BCRAHXS512 = 3,
	/// <summary>
	/// A SHAKE based random number generator using cSHAKE-256
	/// </summary>
	CSR = 4,
	/// <summary>
	/// A SHAKE based random number generator using cSHAKE-512
	/// </summary>
	CSRC512 = 5,
	/// <summary>
	/// A SHAKE based random number generator using cSHAKE-1024
	/// </summary>
	CSRC1024 = 6,
	/// <summary>
	/// An HMAC based random number generator using SHA256
	/// </summary>
	HCR = 7,
	/// <summary>
	/// An HMAC based random number generator using SHA512
	/// </summary>
	HCRS512 = 8
};

NAMESPACE_ENUMERATIONEND
#endif
