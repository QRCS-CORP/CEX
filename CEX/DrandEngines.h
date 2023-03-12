#ifndef CEX_DRANDENGINES_H
#define CEX_DRANDENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The Intel DRNG providers engine configuration type
/// </summary>
enum class DrandEngines : uint8_t
{
	/// <summary>
	/// The random provider is available
	/// </summary>
	None = 0,
	/// <summary>
	/// The random number provider
	/// </summary>
	RdRand = 1,
	/// <summary>
	/// The random seed generator
	/// </summary>
	RdSeed = 2
};

NAMESPACE_ENUMERATIONEND
#endif
