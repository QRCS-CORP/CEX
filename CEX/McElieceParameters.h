#ifndef CEX_MPKCPARAMETERS_H
#define CEX_MPKCPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The McEliece parameter sets enumeration
/// </summary>
enum class McElieceParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S2 parameters (Medium-High Security) A field dimension of 6960 and an error correction capability of 119
	/// </summary>
	MPKCS2N6960T119 = static_cast<byte>(AsymmetricParameters::MPKCS2N6960T119),
	/// <summary>
	/// The S3 parameters (High Security) A field dimension of 8192 and an error correction capability of 128
	/// </summary>
	MPKCS3N8192T128 = static_cast<byte>(AsymmetricParameters::MPKCS3N8192T128)
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
