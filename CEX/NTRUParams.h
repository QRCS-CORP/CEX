#ifndef CEX_NTRUPARAMS_H
#define CEX_NTRUPARAMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The NTRU parameter sets enumeration
/// </summary>
enum class NTRUParams : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The rounded product form L-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	LQ4591N761 = 2,
	/// <summary>
	/// The rounded quotient form S-Prime, modulus of 4591 with 761 coefficients
	/// </summary>
	SQ4591N761 = 3
};

NAMESPACE_ENUMERATIONEND
#endif
