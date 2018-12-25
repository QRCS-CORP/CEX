#ifndef CEX_ASYMMETRICENGINES_H
#define CEX_ASYMMETRICENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher enumeration names
/// </summary>
enum class AsymmetricEngines : byte
{
	/// <summary>
	/// No asymmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A McEliece cipher implementation
	/// </summary>
	McEliece = 1,
	/// <summary>
	/// A Module-LWE cipher implementation
	/// </summary>
	ModuleLWE = 2,
	/// <summary>
	/// An NTRU cipher implementation
	/// </summary>
	NTRU = 3,
	/// <summary>
	/// The Dilithium asymmetric signature scheme
	/// </summary>
	Dilithium = 4,
	/// <summary>
	/// A Ring-LWE cipher implementation
	/// </summary>
	RingLWE = 5,
	/// <summary>
	/// The Sphincs asymmetric signature scheme
	/// </summary>
	Sphincs = 6
};

NAMESPACE_ENUMERATIONEND
#endif



