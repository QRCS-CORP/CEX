#ifndef CEX_RLWEPARAMS_H
#define CEX_RLWEPARAMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The RingLWE parameter sets enumeration
/// </summary>
enum class RLWEParams : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A modulus of 12289 with 1024 coefficients
	/// </summary>
	Q12289N1024 = 1
};

NAMESPACE_ENUMERATIONEND
#endif
