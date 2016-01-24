#ifndef _CEXENGINE_ASYMMETRICENGINES_H
#define _CEXENGINE_ASYMMETRICENGINES_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Asymmetric Encryption Ciphers
/// </summary>
enum class AsymmetricEngines : unsigned int
{
	/// <summary>
	/// An NTRU cipher implementation
	/// </summary>
	NTRU = 1,
	/// <summary>
	/// An Ring-LWE cipher implementation
	/// </summary>
	RingLWE = 2,
	/// <summary>
	/// A Rainbow signing implementation
	/// </summary>
	Rainbow = 4,
	/// <summary>
	/// A Super Isogeny Diffie Hellman implementation
	/// </summary>
	SIDH = 8
};
NAMESPACE_ENUMERATIONEND
#endif



