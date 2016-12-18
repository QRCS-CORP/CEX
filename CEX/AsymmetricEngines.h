#ifndef _CEX_ASYMMETRICENGINES_H
#define _CEX_ASYMMETRICENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher enmumeration names
/// </summary>
enum class AsymmetricEngines : uint8_t
{
	/// <summary>
	/// No asymmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Generalized Merkle Signature Scheme implementation
	/// </summary>
	GMSS = 1,
	/// <summary>
	/// A McEliece cipher implementation
	/// </summary>
	McEliece = 2,
	/// <summary>
	/// An NTRU cipher implementation
	/// </summary>
	NTRU = 4,
	/// <summary>
	/// A Rainbow signature scheme implementation
	/// </summary>
	Rainbow = 8,
	/// <summary>
	/// A Ring-LWE cipher implementation
	/// </summary>
	RingLWE = 16,
	/// <summary>
	/// A Supersingular Isogeny Diffie Hellman implementation
	/// </summary>
	SIDH = 32
};

NAMESPACE_ENUMERATIONEND
#endif



