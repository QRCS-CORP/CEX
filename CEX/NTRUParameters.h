#ifndef CEX_NTRUPARAMETERS_H
#define CEX_NTRUPARAMETERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The NTRU parameter sets enumeration
/// </summary>
enum class NTRUParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (High Security) The rounded product form L-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS1LQ4591N761 = 8,
	/// <summary>
	/// The S2 parameters; (High Security) The rounded quotient form S-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	NTRUS2SQ4591N761 = 9
};

NAMESPACE_ENUMERATIONEND
#endif
