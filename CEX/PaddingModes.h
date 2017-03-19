#ifndef _CEX_PADDINGMODES_H
#define _CEX_PADDINGMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Block cipher padding mode enmumeration names
/// </summary>
enum class PaddingModes : byte
{
	/// <summary>
	/// No padding mode is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// ISO7816 Padding Mode
	/// </summary>
	ISO7816 = 1,
	/// <summary>
	/// PKCS7 Padding Mode
	/// </summary>
	PKCS7 = 2,
	/// <summary>
	/// Trailing Bit Complement Padding Mode
	/// </summary>
	TBC = 4,
	/// <summary>
	/// X923 Padding Mode
	/// </summary>
	X923 = 8
};

NAMESPACE_ENUMERATIONEND
#endif