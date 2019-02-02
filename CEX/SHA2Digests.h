#ifndef CEX_SHA2DIGESTS_H
#define CEX_SHA2DIGESTS_H

#include "CexDomain.h"
#include "Digests.h"

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
	SHA256 = static_cast<byte>(Digests::SHA256),
	/// <summary>
	/// The SHA2-512 digest
	/// </summary>
	SHA512 = static_cast<byte>(Digests::SHA512)
};

class SHA2DigestConvert
{
public:

	/// <summary>
	/// Derive the SHA2Digests formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The SHA2Digests enumeration member</param>
	///
	/// <returns>The matching SHA2Digests string name</returns>
	static std::string ToName(SHA2Digests Enumeral);

	/// <summary>
	/// Derive the SHA2Digests enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The SHA2Digests string name</param>
	///
	/// <returns>The matching SHA2Digests enumeration type name</returns>
	static SHA2Digests FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
