#ifndef CEX_MPKCPARAMETERS_H
#define CEX_MPKCPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The McEliece parameter sets enumeration
/// </summary>
enum class McElieceParameters : uint8_t
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The McEliece S3 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 96
	/// </summary>
	MPKCS3N4608T96 = static_cast<uint8_t>(AsymmetricParameters::MPKCS3N4608T96),
	/// <summary>
	/// The McEliece S3 parameters (Medium-High Security) A finite field of 13 and an error correction capability of 119
	/// </summary>
	MPKCS3N6960T119 = static_cast<uint8_t>(AsymmetricParameters::MPKCS3N6960T119),
	/// <summary>
	/// The McEliece S4 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS4N6688T128 = static_cast<uint8_t>(AsymmetricParameters::MPKCS4N6688T128),
	/// <summary>
	/// The McEliece S5 parameters (High Security) A finite field of 13 and an error correction capability of 128
	/// </summary>
	MPKCS5N8192T128 = static_cast<uint8_t>(AsymmetricParameters::MPKCS5N8192T128),
};

class McElieceParameterConvert
{
public:

	/// <summary>
	/// Derive the McElieceParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The McElieceParameters enumeration member</param>
	///
	/// <returns>The matching McElieceParameters string name</returns>
	static std::string ToName(McElieceParameters Enumeral);

	/// <summary>
	/// Derive the McElieceParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The McElieceParameters string name</param>
	///
	/// <returns>The matching McElieceParameters enumeration type name</returns>
	static McElieceParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
