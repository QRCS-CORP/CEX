#ifndef CEX_DILITHIUMPARAMETERS_H
#define CEX_DILITHIUMPARAMETERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The Dilithium parameter sets enumeration
/// </summary>
enum class DilithiumParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Medium Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS1256Q8380417 = 1,
	/// <summary>
	/// The S2 parameters; (High Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS2N256Q8380417 = 2,
	/// <summary>
	/// The S3 parameters; (Highest Security) using a modulus of 8380417 with 256 coefficients
	/// </summary>
	DLMS3N256Q8380417 = 3,
};

NAMESPACE_ENUMERATIONEND
#endif
