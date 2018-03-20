#ifndef CEX_SHAKEMODES_H
#define CEX_SHAKEMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The type of SHAKE KDF variant.
/// <para>Must coincide with Digests/Kdfs enumeration.</para>
/// </summary>
enum class ShakeModes : byte
{
	/// <summary>
	/// No SHAKE mode is selected
	/// </summary>
	None = 0,
	/// <summary>
	/// The SHAKE128 XOF function
	/// </summary>
	SHAKE128 = 8,
	/// <summary>
	/// The SHAKE256 XOF function
	/// </summary>
	SHAKE256 = 9,
	/// <summary>
	/// The SHAKE512 XOF function
	/// </summary>
	SHAKE512 = 10,
	/// <summary>
	/// The SHAKE1024 XOF function
	/// </summary>
	SHAKE1024 = 11
};

NAMESPACE_ENUMERATIONEND
#endif
