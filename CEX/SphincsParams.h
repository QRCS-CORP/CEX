#ifndef CEX_SPHINCSPARAMS_H
#define CEX_SPHINCSPARAMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The Sphincs parameter sets enumeration
/// </summary>
enum class SphincsParams : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// 
	/// </summary>
	SHAKE256F128 = 2
};

NAMESPACE_ENUMERATIONEND
#endif
