#ifndef CEX_MLWEPARAMETERS_H
#define CEX_MLWEPARAMETERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The ModuleLWE parameter sets enumeration
/// </summary>
enum class MLWEParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S2 parameters; (Medium Security) A modulus of 7681 with 256 coefficients and K of 2
	/// </summary>
	MLWES2Q7681N256 = 4,
	/// <summary>
	/// The S3 parameters; (High Security) A modulus of 7681 with 256 coefficients and K of 3
	/// </summary>
	MLWES3Q7681N256 = 5,
	/// <summary>
	/// The S4 parameters; (Highest Security) A modulus of 7681 with 256 coefficients and K of 4
	/// </summary>
	MLWES4Q7681N256 = 6
};

NAMESPACE_ENUMERATIONEND
#endif
