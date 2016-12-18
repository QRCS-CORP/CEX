#ifndef _CEX_PRNGS_H
#define _CEX_PRNGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Pseudo Random Generators enmumeration names
/// </summary>
enum class Prngs : uint8_t
{
	/// <summary>
	/// No prng is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Symmetric Cipher Counter mode random number generator
	/// </summary>
	CMR = 1,
	/// <summary>
	/// A Digest Counter mode random number generator
	/// </summary>
	DCR = 2,
	/// <summary>
	/// An implementation of a passphrase based PKCS#5 random number generator
	/// </summary>
	PBR = 4
};

NAMESPACE_ENUMERATIONEND
#endif