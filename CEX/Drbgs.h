#ifndef _CEX_GENERATORS_H
#define _CEX_GENERATORS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Pseudo Random Generator enmumeration names
/// </summary>
enum class Drbgs : uint8_t
{
	/// <summary>
	/// No generator is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An implementation of a Encryption Counter based DRBG
	/// </summary>
	CMG = 1,
	/// <summary>
	/// An implementation of a Digest Counter based DRBG
	/// </summary>
	DCG = 2,
	/// <summary>
	/// An implementation of an HMAC based DRBG
	/// </summary>
	HMG = 4
};

NAMESPACE_ENUMERATIONEND
#endif