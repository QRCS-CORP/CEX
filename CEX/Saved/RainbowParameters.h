#ifndef CEX_RAINBOWPARAMETERS_H
#define CEX_RAINBOWPARAMETERS_H

#include "CexDomain.h"
#include "AsymmetricParameters.h"

NAMESPACE_ENUMERATION

/// <summary>
/// The RAINBOW+ parameter sets enumeration
/// </summary>
enum class RainbowParameters : byte
{
	/// <summary>
	/// No parameter is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// The S1 parameters; (Medium Security) The Rainbow SHAKE-256, S128 parameter set
	/// </summary>
	RNBWS1S128SHAKE256 = static_cast<byte>(AsymmetricParameters::RNBWS1S128SHAKE256),
	/// <summary>
	/// The S2 parameters; (High Security) The Rainbow SHAKE-512, S192 parameter set
	/// </summary>
	RNBWS2S192SHAKE512 = static_cast<byte>(AsymmetricParameters::RNBWS2S192SHAKE512),
	/// <summary>
	/// The S3 parameters; (Highest Security) The Rainbow SHAKE-512, S256 parameter set
	/// </summary>
	RNBWS3S256SHAKE512 = static_cast<byte>(AsymmetricParameters::RNBWS3S256SHAKE512)
};

class RainbowParameterConvert
{
public:

	/// <summary>
	/// Derive the RainbowParameters formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The RainbowParameters enumeration member</param>
	///
	/// <returns>The matching RainbowParameters string name</returns>
	static std::string ToName(RainbowParameters Enumeral);

	/// <summary>
	/// Derive the RainbowParameters enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The RainbowParameters string name</param>
	///
	/// <returns>The matching RainbowParameters enumeration type name</returns>
	static RainbowParameters FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
