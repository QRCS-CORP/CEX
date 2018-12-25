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
	/// The S1 parameters; (Medium Security) The Sphincs SHAKE128, F256 parameter set
	/// </summary>
	SPXS128F256 = 12,
	/// <summary>
	/// The S2 parameters; (High Security) The Sphincs SHAKE256, F256 parameter set
	/// </summary>
	SPXS256F256 = 13,
	/// <summary>
	/// The S3 parameters; (Highest Security) The experimental Sphincs SHAKE512, F256 parameter set
	/// </summary>
	SPXS512F256 = 14
};

NAMESPACE_ENUMERATIONEND
#endif
