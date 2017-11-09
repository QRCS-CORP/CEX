#ifndef CEX_MACS_H
#define CEX_MACS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Message Authentication Code generator enmumeration names
/// </summary>
enum class Macs : byte
{
	/// <summary>
	/// No kdf is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Cipher based Message Authentication Code generator (CMAC)
	/// </summary>
	CMAC = 1,
	/// <summary>
	/// A Hash based Message Authentication Code generator (HMAC)
	/// </summary>
	HMAC = 2,
	/// <summary>
	/// A Cipher based Message Authentication Code generator (GMAC)
	/// </summary>
	GMAC = 3,
	/// <summary>
	/// The Poly1305 Message Authentication Code generator
	/// </summary>
	Poly1305 = 4
};

NAMESPACE_ENUMERATIONEND
#endif