#ifndef CEX_ASYMMETRICENGINES_H
#define CEX_ASYMMETRICENGINES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Asymmetric cipher enmumeration names
/// </summary>
enum class AsymmetricEngines : byte
{
	/// <summary>
	/// No asymmetric cipher is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An Elliptic Curve Diffie Hellman cipher implementation
	/// </summary>
	ECDH = 1,
	/// <summary>
	/// Elliptic Curve Digital Signature Algorithm
	/// </summary>
	ECDSA = 2,
	/// <summary>
	/// A Generalized Merkle Signature Scheme implementation
	/// </summary>
	GMSS = 3,
	/// <summary>
	/// A McEliece cipher implementation
	/// </summary>
	McEliece = 4,
	/// <summary>
	/// A Module-LWE cipher implementation
	/// </summary>
	ModuleLWE = 5,
	/// <summary>
	/// An NTRU cipher implementation
	/// </summary>
	NTRU = 6,
	/// <summary>
	/// A Ring-LWE cipher implementation
	/// </summary>
	RingLWE = 7
};

NAMESPACE_ENUMERATIONEND
#endif



