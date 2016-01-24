#ifndef _CEXENGINE_KDFGENERATORS_H
#define _CEXENGINE_KDFGENERATORS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Random Generator Digest KDFs
/// </summary>
enum class KdfGenerators : unsigned int
{
	/// <summary>
	/// A Block Cipher CTR generator
	/// </summary>
	CTRDrbg = 1,
	/// <summary>
	/// An implementation of a Digest Counter based DRBG
	/// </summary>
	DGCDRBG = 2,
	/// <summary>
	/// A Hash based Key Derivation Function HKDF
	/// </summary>
	HKDF = 4,
	/// <summary>
	/// An implementation of the Hash based KDF KDF2 DRBG
	/// </summary>
	KDF2Drbg = 8,
	/// <summary>
	/// An implementation of PBKDF2 Version 2
	/// </summary>
	PBKDF2 = 16,
	/// <summary>
	/// An implementation of a Salsa20 counter generator
	/// </summary>
	SP20Drbg = 32,
};
NAMESPACE_ENUMERATIONEND

#endif