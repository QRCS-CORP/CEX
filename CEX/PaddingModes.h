#ifndef CEX_PADDINGMODES_H
#define CEX_PADDINGMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Block cipher padding mode enumeration names
/// </summary>
enum class PaddingModes : byte
{
	/// <summary>
	/// No padding mode is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// ESP Padding Mode
	/// </summary>
	ESP = 1,
	/// <summary>
	/// PKCS7 Padding Mode
	/// </summary>
	PKCS7 = 2,
	/// <summary>
	/// X923 Padding Mode
	/// </summary>
	X923 = 3,
	/// <summary>
	/// Zero and One Padding Mode
	/// </summary>
	ZeroOne = 4
};

class PaddingModeConvert
{
public:

	/// <summary>
	/// Derive the PaddingModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The PaddingModes enumeration member</param>
	///
	/// <returns>The matching PaddingModes string name</returns>
	static std::string ToName(PaddingModes Enumeral);

	/// <summary>
	/// Derive the PaddingModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The PaddingModes string name</param>
	///
	/// <returns>The matching PaddingModes enumeration type name</returns>
	static PaddingModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
