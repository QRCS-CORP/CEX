#ifndef CEX_STREAMAUTHENTICATORS_H
#define CEX_STREAMAUTHENTICATORS_H

#include "CexDomain.h"
#include "Macs.h"

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
	HMACSHA256 = static_cast<byte>(Macs::HMACSHA256),
	/// <summary>
	/// A HMAC(SHA512) message authentication code generator
	/// </summary>
	HMACSHA512 = static_cast<byte>(Macs::HMACSHA512),
	/// <summary>
	/// The KMAC-256 message authentication code generator
	/// </summary>
	KMAC256 = static_cast<byte>(Macs::KMAC256),
	/// <summary>
	/// The KMAC-512 message authentication code generator
	/// </summary>
	KMAC512 = static_cast<byte>(Macs::KMAC512),
	/// <summary>
	/// The KMAC-1024 message authentication code generator (experimental)
	/// </summary>
	KMAC1024 = static_cast<byte>(Macs::KMAC1024)
};

class StreamAuthenticatorConvert
{
public:

	/// <summary>
	/// Derive the StreamAuthenticators formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The StreamAuthenticators enumeration member</param>
	///
	/// <returns>The matching StreamAuthenticators string name</returns>
	static std::string ToName(StreamAuthenticators Enumeral);

	/// <summary>
	/// Derive the StreamAuthenticators enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The StreamAuthenticators string name</param>
	///
	/// <returns>The matching StreamAuthenticators enumeration type name</returns>
	static StreamAuthenticators FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
