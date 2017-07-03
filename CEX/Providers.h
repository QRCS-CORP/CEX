#ifndef _CEX_PROVIDERS_H
#define _CEX_PROVIDERS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Cryptographic entropy provider enumeration names
/// </summary>
enum class Providers : byte
{
	/// <summary>
	/// No provider is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The Auto Collection seed Provider (recommended), uses all sources to construct seeds
	/// </summary>
	ACP = 1,
	/// <summary>
	/// A CPU Jitter based generator using cpu jitter based entropy
	/// </summary>
	CJP = 2,
	/// <summary>
	/// An entropy provider using the system random provider
	/// </summary>
	CSP = 4,
	/// <summary>
	/// An entropy provider using collected system entropy
	/// </summary>
	ECP = 8,
	/// <summary>
	/// A entropy provider using the Intel RDSeed provider
	/// </summary>
	RDP = 16
};

NAMESPACE_ENUMERATIONEND
#endif