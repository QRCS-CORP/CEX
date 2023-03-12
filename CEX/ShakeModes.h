#ifndef CEX_SHAKEMODES_H
#define CEX_SHAKEMODES_H

#include "CexDomain.h"
#include "Digests.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The type of SHAKE KDF variant.
/// <para>Must coincide with Digests/Kdfs enumeration.</para>
/// </summary>
enum class ShakeModes : uint8_t
{
	/// <summary>
	/// No SHAKE mode is selected
	/// </summary>
	None = static_cast<uint8_t>(Digests::None),
	/// <summary>
	/// The SHAKE128 XOF function
	/// </summary>
	SHAKE128 = static_cast<uint8_t>(Digests::SHAKE128),
	/// <summary>
	/// The SHAKE256 XOF function
	/// </summary>
	SHAKE256 = static_cast<uint8_t>(Digests::SHAKE256),
	/// <summary>
	/// The SHAKE512 XOF function
	/// </summary>
	SHAKE512 = static_cast<uint8_t>(Digests::SHAKE512)
};

class ShakeModeConvert
{
public:

	/// <summary>
	/// Derive the ShakeModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The ShakeModes enumeration member</param>
	///
	/// <returns>The matching ShakeModes string name</returns>
	static std::string ToName(ShakeModes Enumeral);

	/// <summary>
	/// Derive the ShakeModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The ShakeModes string name</param>
	///
	/// <returns>The matching ShakeModes enumeration type name</returns>
	static ShakeModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
