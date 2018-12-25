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
	/// A Symmetric Cipher Counter mode random number generator
	/// </summary>
	BCR = 1,
	/// <summary>
	/// A cSHAKE based random number generator
	/// </summary>
	CSR = 2,
	/// <summary>
	/// An HMAC based random number generator
	/// </summary>
	HCR = 3,
	/// <summary>
	/// An implementation of a passphrase based PKCS#5 random number generator
	/// </summary>
	PBR = 4
};

NAMESPACE_ENUMERATIONEND
#endif
