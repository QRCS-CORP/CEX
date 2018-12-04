#ifndef CEX_RLWEPARAMETERS_H
#define CEX_RLWEPARAMETERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The RingLWE parameter sets enumeration
/// </summary>
enum class RLWEParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (High Security) A modulus of 12289 with 1024 coefficients
	/// </summary>
	RLWES1Q12289N1024 = 1,
	/// <summary>
	/// A modulus of 12289 with 2048 coefficients
	/// </summary>
	RLWES2Q12289N2048 = 2
};

NAMESPACE_ENUMERATIONEND
#endif
