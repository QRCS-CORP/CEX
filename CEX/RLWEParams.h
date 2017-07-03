#ifndef _CEX_RLWEPARAMS_H
#define _CEX_RLWEPARAMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The RingLWE parameter sets enumeration
/// </summary>
enum class RLWEParams : ushort
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A modulus of 12289 with 1024 coefficients
	/// </summary>
	Q12289N1024 = 1
	/// <summary>
	/// A modulus of 40961 with 1024 coefficients
	/// </summary>
	//Q40961N1024 = 2
};

NAMESPACE_ENUMERATIONEND
#endif