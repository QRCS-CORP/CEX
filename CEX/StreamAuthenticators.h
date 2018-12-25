#ifndef CEX_STREAMAUTHENTICATORS_H
#define CEX_STREAMAUTHENTICATORS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Message Authentication Code generator enumeration names
/// </summary>
enum class StreamAuthenticators : byte
{
	/// <summary>
	/// No MAC is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A HMAC(SHA256) message authentication code generator
	/// </summary>
	HMACSHA256 = 1,
	/// <summary>
	/// A HMAC(SHA512) message authentication code generator
	/// </summary>
	HMACSHA512 = 2,
	/// <summary>
	/// The KMAC-256 message authentication code generator
	/// </summary>
	KMAC256 = 3,
	/// <summary>
	/// The KMAC-512 message authentication code generator
	/// </summary>
	KMAC512 = 4, 
	/// <summary>
	/// The KMAC-1024 message authentication code generator (experimental)
	/// </summary>
	KMAC1024 = 5
};

NAMESPACE_ENUMERATIONEND
#endif
