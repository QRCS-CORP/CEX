#ifndef CEX_SECURITYPOLICY_H
#define CEX_SECURITYPOLICY_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Cryptographic strength security policy
/// </summary>
enum class SecurityPolicy : uint8_t
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

class SecurityPolicyConvert
{
public:

	/// <summary>
	/// Derive the SecurityPolicy formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The SecurityPolicy enumeration member</param>
	///
	/// <returns>The matching SecurityPolicy string name</returns>
	static std::string ToName(SecurityPolicy Enumeral);

	/// <summary>
	/// Derive the SecurityPolicy enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The SecurityPolicy string name</param>
	///
	/// <returns>The matching SecurityPolicy enumeration type name</returns>
	static SecurityPolicy FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
