#ifndef _CEXENGINE_MACS_H
#define _CEXENGINE_MACS_H

#include "Common.h"

NAMESPACE_ENUMERATION
/// <summary>
/// Message Authentication Code Generators
/// </summary>
enum class Macs : unsigned int
{
	/// <summary>
	/// A Cipher based Message Authentication Code wrapper (CMAC)
	/// </summary>
	CMAC = 1,
	/// <summary>
	/// A Hash based Message Authentication Code wrapper (HMAC)
	/// </summary>
	HMAC = 2,
	/// <summary>
	/// A Variably Modified Permutation Composition based Message Authentication Code (VMPC-MAC)
	/// </summary>
	VMAC = 4
};
NAMESPACE_ENUMERATIONEND

#endif