#ifndef CEX_KMACMODES_H
#define CEX_KMACMODES_H

#include "CexDomain.h"
#include "Macs.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The type of KMAC MAC variant.
/// </summary>
enum class KmacModes : byte
{
	/// <summary>
	/// No KMAC mode is selected
	/// </summary>
	None = static_cast<byte>(Macs::None),
	/// <summary>
	/// The KMAC128 MAC function
	/// </summary>
	KMAC128 = static_cast<byte>(Macs::KMAC128),
	/// <summary>
	/// The KMAC256 MAC function
	/// </summary>
	KMAC256 = static_cast<byte>(Macs::KMAC256),
	/// <summary>
	/// The KMAC512 MAC function
	/// </summary>
	KMAC512 = static_cast<byte>(Macs::KMAC512),
	/// <summary>
	/// The KMAC1024 MAC function
	/// </summary>
	KMAC1024 = static_cast<byte>(Macs::KMAC1024)
};

class KmacModeConvert
{
public:

	/// <summary>
	/// Derive the KmacModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The KmacModes enumeration member</param>
	///
	/// <returns>The matching KmacModes string name</returns>
	static std::string ToName(KmacModes Enumeral);

	/// <summary>
	/// Derive the KmacModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The KmacModes string name</param>
	///
	/// <returns>The matching KmacModes enumeration type name</returns>
	static KmacModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
