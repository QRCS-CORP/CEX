#ifndef CEX_MLWEPARAMS_H
#define CEX_MLWEPARAMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The ModuleLWE parameter sets enumeration
/// </summary>
enum class MLWEParams : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	Q7681N256K2 = 2,
	/// <summary>
	/// A modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	Q7681N256K3 = 3,
	/// <summary>
	/// A modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	Q7681N256K4 = 4
};

NAMESPACE_ENUMERATIONEND
#endif
