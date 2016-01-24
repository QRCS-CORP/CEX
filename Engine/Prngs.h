#ifndef _CEXENGINE_PRNGS_H
#define _CEXENGINE_PRNGS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Pseudo Random Generators
/// </summary>
enum class Prngs : unsigned int
{
	/// <summary>
	///  A Secure PRNG using RNGCryptoServiceProvider
	/// </summary>
	CSPPrng = 1,
	/// <summary>
	/// A Symmetric Cipher Counter mode random number generator
	/// </summary>
	CTRPrng = 2,
	/// <summary>
	/// A Digest Counter mode random number generator
	/// </summary>
	DGCPrng = 4,
	/// <summary>
	/// An implementation of a passphrase based PKCS#5 random number generator
	/// </summary>
	PPBPrng = 8,
	/// <summary>
	/// An implementation of a Salsa20 Counter based Prng
	/// </summary>
	SP20Prng = 16
};
NAMESPACE_ENUMERATIONEND

#endif