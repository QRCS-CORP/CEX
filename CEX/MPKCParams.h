#ifndef _CEX_MPKCPARAMS_H
#define _CEX_MPKCPARAMS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The McEliece parameter sets enumeration
/// </summary>
enum class MPKCParams : ushort
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A finite field of 12 and an error correction capability of 62
	/// </summary>
	G12T62 = 1
	/// <summary>
	/// A finite field of ?? and an error correction capability of ??
	/// </summary>
	//G??T?? = 2
};

NAMESPACE_ENUMERATIONEND
#endif