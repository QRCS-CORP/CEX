#ifndef CEX_PRNGS_H
#define CEX_PRNGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Pseudo Random Generators enmumeration names
/// </summary>
enum class Prngs : byte
{
	/// <summary>
	/// No prng is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Symmetric Cipher Counter mode random number generator
	/// </summary>
	BCR = 1,
	/// <summary>
	/// A Digest Counter mode random number generator
	/// </summary>
	DCR = 2,
	/// <summary>
	/// An HMAC based random number generator
	/// </summary>
	HCR = 4,
	/// <summary>
	/// An implementation of a passphrase based PKCS#5 random number generator
	/// </summary>
	PBR = 8
};

NAMESPACE_ENUMERATIONEND
#endif