#ifndef CEX_THREEFISHMODES_H
#define CEX_THREEFISHMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Threefish stream cipher operation-modes enmumeration names
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
	Threefish256 = 66,
	/// <summary>
	/// The Threefish 512-bit stream cipher
	/// </summary>
	Threefish512 = 67,
	/// <summary>
	/// The Threefish 1024-bit stream cipher
	/// </summary>
	Threefish1024 = 68
};

NAMESPACE_ENUMERATIONEND
#endif
