#ifndef CEX_DRBGS_H
#define CEX_DRBGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Pseudo Random Generator enumeration names
/// </summary>
enum class Drbgs : byte
{
	/// <summary>
	/// No generator is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Block-cipher Counter mode Deterministic Random Bit Generator
	/// </summary>
	BCG = 1,
	/// <summary>
	/// A cSHAKE Deterministic Random Bit Generator
	/// </summary>
	CSG = 2,
	/// <summary>
	/// A HMAC Counter  Deterministic Random Bit Generator
	/// </summary>
	HCG = 3
};

NAMESPACE_ENUMERATIONEND
#endif
