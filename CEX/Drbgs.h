#ifndef _CEX_GENERATORS_H
#define _CEX_GENERATORS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Pseudo Random Generator enmumeration names
/// </summary>
enum class Drbgs : byte
{
	/// <summary>
	/// No generator is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// An implementation of a Block Counter mode Generator
	/// </summary>
	BCG = 1,
	/// <summary>
	/// An implementation of a Digest Counter Generator
	/// </summary>
	DCG = 2,
	/// <summary>
	/// An implementation of an HMAC Counter Generator
	/// </summary>
	HCG = 4
};

NAMESPACE_ENUMERATIONEND
#endif