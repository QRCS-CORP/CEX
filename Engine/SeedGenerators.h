#ifndef _CEXENGINE_SEEDGENERATORS_H
#define _CEXENGINE_SEEDGENERATORS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Seed Generators
/// </summary>
enum class SeedGenerators : unsigned int
{
	/// <summary>
	/// A Secure Seed Generator using RNGCryptoServiceProvider
	/// </summary>
	CSPRsg = 1,
	/// <summary>
	/// A Secure Seed Generator using the entropy pool and an ISAAC generator
	/// </summary>
	ISCRsg = 2,
	/// <summary>
	/// A (fast but less secure) Seed Generator using the entropy pool and an XorShift+ generator
	/// </summary>
	XSPRsg = 4
};

NAMESPACE_ENUMERATIONEND
#endif