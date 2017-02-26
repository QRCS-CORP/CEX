#ifndef _CEX_MACS_H
#define _CEX_MACS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Message Authentication Code generator enmumeration names
/// </summary>
enum class Macs : uint8_t
{
	/// <summary>
	/// No kdf is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Cipher based Message Authentication Code wrapper (CMAC)
	/// </summary>
	CMAC = 1,
	/// <summary>
	/// A Hash based Message Authentication Code wrapper (HMAC)
	/// </summary>
	HMAC = 2,
	/// <summary>
	/// A Cipher based Message Authentication Code wrapper (GMAC)
	/// </summary>
	GMAC = 4
};

NAMESPACE_ENUMERATIONEND
#endif