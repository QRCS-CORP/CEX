#ifndef CEX_KPAMODES_H
#define CEX_KPAMODES_H

#include "CexDomain.h"
#include "Macs.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The type of KBA MAC variant.
/// </summary>
enum class KpaModes : uint8_t
{
	/// <summary>
	/// No KMAC mode is selected
	/// </summary>
	None = static_cast<uint8_t>(Macs::None),
	/// <summary>
	/// The KPA128 MAC function
	/// </summary>
	KPA128 = static_cast<uint8_t>(Macs::KPA128),
	/// <summary>
	/// The KPA256 MAC function
	/// </summary>
	KPA256 = static_cast<uint8_t>(Macs::KPA256),
	/// <summary>
	/// The KPA512 MAC function
	/// </summary>
	KPA512 = static_cast<uint8_t>(Macs::KPA512)
};

class KbaModeConvert
{
public:

	/// <summary>
	/// Derive the KpaModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The KpaModes enumeration member</param>
	///
	/// <returns>The matching KpaModes string name</returns>
	static std::string ToName(KpaModes Enumeral);

	/// <summary>
	/// Derive the KpaModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The KpaModes string name</param>
	///
	/// <returns>The matching KpaModes enumeration type name</returns>
	static KpaModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
