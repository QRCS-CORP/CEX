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
	/// ISO7816 Padding Mode
	/// </summary>
	ISO7816 = 2,
	/// <summary>
	/// PKCS7 Padding Mode
	/// </summary>
	PKCS7 = 3,
	/// <summary>
	/// X923 Padding Mode
	/// </summary>
	X923 = 4,
	/// <summary>
	/// Zero and One Padding Mode
	/// </summary>
	ZeroOne = 5
};

NAMESPACE_ENUMERATIONEND
#endif
