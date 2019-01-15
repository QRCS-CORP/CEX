#ifndef CEX_THREEFISHMODES_H
#define CEX_THREEFISHMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Threefish stream cipher operation-modes enumeration names
/// </summary>
enum class ThreefishModes : byte
{
	/// <summary>
	/// No Threefish mode has been selected
	/// </summary>
	None = 0,
	/// <summary>
	/// The Threefish 256-bit stream cipher
	/// </summary>
	Threefish256 = 128,
	/// <summary>
	/// The Threefish 256-bit stream cipher authenticated with KMAC256
	/// </summary>
	Threefish256AE = 129,
	/// <summary>
	/// The Threefish 512-bit stream cipher
	/// </summary>
	Threefish512 = 130,
	/// <summary>
	/// The Threefish 512-bit stream cipher authenticated with KMAC512
	/// </summary>
	Threefish512AE = 131,
	/// <summary>
	/// The Threefish 1024-bit stream cipher
	/// </summary>
	Threefish1024 = 132,
	/// <summary>
	/// The Threefish 1024-bit stream cipher authenticated with KMAC1024
	/// </summary>
	Threefish1024AE = 133
};

NAMESPACE_ENUMERATIONEND
#endif
