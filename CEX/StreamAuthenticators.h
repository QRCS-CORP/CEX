#ifndef CEX_STREAMAUTHENTICATORS_H
#define CEX_STREAMAUTHENTICATORS_H

#include "CexDomain.h"
#include "Macs.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Message Authentication Code generator enumeration names
/// </summary>
enum class StreamAuthenticators : uint8_t
{
	/// <summary>
	/// No MAC is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Keccak-based Parallel Authentication code generator
	/// </summary>
	KPA = 1,
	/// <summary>
	/// The KMAC-256 message authentication code generator
	/// </summary>
	KMAC = 2,
	/// <summary>
	/// A HMAC(SHA2256) message authentication code generator
	/// </summary>
	HMACSHA2256 = static_cast<uint8_t>(Macs::HMACSHA2256), 
	/// <summary>
	/// A HMAC(SHA2512) message authentication code generator
	/// </summary>
	HMACSHA2512 = static_cast<uint8_t>(Macs::HMACSHA2512),
	/// <summary>
	/// The KMAC-256 message authentication code generator
	/// </summary>
	KMAC256 = static_cast<uint8_t>(Macs::KMAC256),
	/// <summary>
	/// The KMAC-512 message authentication code generator
	/// </summary>
	KMAC512 = static_cast<uint8_t>(Macs::KMAC512),
	/// <summary>
	/// The Poly1305 message authentication code generator
	/// </summary>
	Poly1305 = static_cast<uint8_t>(Macs::Poly1305)
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
