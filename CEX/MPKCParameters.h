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
	/// The S1 parameters (Medium Security) A finite field of 12 and an error correction capability of 62
	/// </summary>
	MPKCS1M12T62 = static_cast<byte>(AsymmetricTransforms::MPKCS1M12T62)
	/// <summary>
	/// A finite field of ?? and an error correction capability of ??
	/// </summary>
	//G??T?? = 8
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
