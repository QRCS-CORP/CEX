#ifndef CEX_SPHINCSPARAMETERS_H
#define CEX_SPHINCSPARAMETERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The SPHINCS+ parameter sets enumeration
/// </summary>
enum class SphincsParameters : byte
{
	/// <summary>
	/// No parameter is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Sphincs SHAKE256, F256 parameter set
	/// </summary>
	SphincsSK256F256 = 1,
	/// <summary>
	/// The Sphincs SHAKE128, F256 parameter set
	/// </summary>
	SphincsSK128F256 = 2
};

NAMESPACE_ENUMERATIONEND
#endif
