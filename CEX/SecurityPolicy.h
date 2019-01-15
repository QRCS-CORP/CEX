#ifndef CEX_SECURITYPOLICY_H
#define CEX_SECURITYPOLICY_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Cryptographic strength security policy
/// </summary>
enum class SecurityPolicy : byte
{
	/// <summary>
	/// No policy is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A 256-bit security policy
	/// </summary>
	SPL256 = 1,
	/// <summary>
	/// A 256-bit security policy that provides authentication
	/// </summary>
	SPL256AE = 2,
	/// <summary>
	/// A 512-bit security policy
	/// </summary>
	SPL512 = 3,
	/// <summary>
	/// A 512-bit security policy that provides authentication
	/// </summary>
	SPL512AE = 4,
	/// <summary>
	/// A 1024-bit security policy
	/// </summary>
	SPL1024 = 5,
	/// <summary>
	/// A 1024-bit security policy that provides authentication
	/// </summary>
	SPL1024AE = 6
};

NAMESPACE_ENUMERATIONEND
#endif
