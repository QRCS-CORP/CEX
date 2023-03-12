#ifndef CEX_DRBGS_H
#define CEX_DRBGS_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Pseudo Random Generator enumeration names
/// </summary>
enum class Drbgs : uint8_t
{
	/// <summary>
	/// No generator is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// A Block-cipher Counter mode Deterministic Random Bit Generator
	/// </summary>
	BCG = 1,
	/// <summary>
	/// A cSHAKE Deterministic Random Bit Generator
	/// </summary>
	CSG = 2,
	/// <summary>
	/// A HMAC Counter  Deterministic Random Bit Generator
	/// </summary>
	HCG = 3
};

class DrbgConvert
{
public:

	/// <summary>
	/// Derive the Drbgs formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The Drbgs enumeration member</param>
	///
	/// <returns>The matching Drbgs string name</returns>
	static std::string ToName(Drbgs Enumeral);

	/// <summary>
	/// Derive the Drbgs enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The Drbgs string name</param>
	///
	/// <returns>The matching Drbgs enumeration type name</returns>
	static Drbgs FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
