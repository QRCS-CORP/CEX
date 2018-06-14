#ifndef CEX_SHA2DIGESTS_H
#define CEX_SHA2DIGESTS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Implementations of the SHA2 family of message digests
/// </summary>
enum class SHA2Digests : byte
{
	/// <summary>
	/// No message digest is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The SHA2-256 digest
	/// </summary>
	SHA256 = 6,
	/// <summary>
	/// The SHA2-512 digest
	/// </summary>
	SHA512 = 7
};

NAMESPACE_ENUMERATIONEND
#endif
