#ifndef _CEXENGINE_PADDINGMODES_H
#define _CEXENGINE_PADDINGMODES_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Block Cipher Padding Modes
/// </summary>
enum class PaddingModes : unsigned int
{
	/// <summary>
	/// Specify None if the input should not require padding (block aligned)
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