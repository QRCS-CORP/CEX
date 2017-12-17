#ifndef CEX_SHAKEMODES_H
#define CEX_SHAKEMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The type of SHAKE variant
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
	SHAKE128 = 1,
	/// <summary>
	/// The SHAKE256 XOF function
	/// </summary>
	SHAKE256 = 2,
	/// <summary>
	/// The SHAKE512 XOF function
	/// </summary>
	SHAKE512 = 3,
	/// <summary>
	/// The SHAKE1024 XOF function
	/// </summary>
	SHAKE1024 = 4
};

NAMESPACE_ENUMERATIONEND
#endif