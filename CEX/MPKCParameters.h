#ifndef CEX_MPKCPARAMETERS_H
#define CEX_MPKCPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricTransforms.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The McEliece parameter sets enumeration
/// </summary>
enum class MPKCParameters : byte
{
	/// <summary>
	/// No parameter set is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters (Medium Security) A field dimension of 4096 and an error correction capability of 62
	/// </summary>
	MPKCS1N4096T62 = static_cast<byte>(AsymmetricTransforms::MPKCS1N4096T62),
	/// <summary>
	/// The S2 parameters (Medium-High Security) A field dimension of 6960 and an error correction capability of 119
	/// </summary>
	MPKCS1N6960T119 = static_cast<byte>(AsymmetricTransforms::MPKCS1N6960T119),
	/// <summary>
	/// The S3 parameters (High Security) A field dimension of 8192 and an error correction capability of 128
	/// </summary>
	MPKCS1N8192T128 = static_cast<byte>(AsymmetricTransforms::MPKCS1N8192T128)
};

class MPKCParameterConvert
{
public:

	/// <summary>
	/// Derive the MPKCParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The MPKCParameters enumeration member</param>
	///
	/// <returns>The matching MPKCParameters string name</returns>
	static std::string ToName(MPKCParameters Enumeral);

	/// <summary>
	/// Derive the MPKCParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The MPKCParameters string name</param>
	///
	/// <returns>The matching MPKCParameters enumeration type name</returns>
	static MPKCParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
