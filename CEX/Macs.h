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
	/// No MAC is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Cipher based Message Authentication Code generator (CMAC)
	/// </summary>
	CMAC = 1,
	/// <summary>
	/// A Cipher based Message Authentication Code generator (GMAC)
	/// </summary>
	GMAC = 2,
	/// <summary>
	/// A Hash based Message Authentication Code generator (HMAC)
	/// </summary>
	HMAC = 3,
	/// <summary>
	/// The Keccak based Message Authentication Code generator (KMAC)
	/// </summary>
	KMAC = 4,
	/// <summary>
	/// The Poly1305 Message Authentication Code generator
	/// </summary>
	Poly1305 = 5
};

NAMESPACE_ENUMERATIONEND
#endif
