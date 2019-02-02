#ifndef CEX_AEADMODES_H
#define CEX_AEADMODES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// Symmetric AEAD cipher mode enumeration names
/// </summary>
enum class AeadModes : byte
{
	/// <summary>
	/// No cipher mode is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// Encrypt and Authenticate AEAD Mode
	/// </summary>
	EAX = 5,
	/// <summary>
	/// Galois Counter AEAD Mode
	/// </summary>
	GCM = 6
};

class AeadModeConvert
{
public:

	/// <summary>
	/// Derive the AeadModes formal string name from the enumeration name
	/// </summary>
	/// 
	/// <param name="Enumeral">The AeadModes enumeration member</param>
	///
	/// <returns>The matching AeadModes string name</returns>
	static std::string ToName(AeadModes Enumeral);

	/// <summary>
	/// Derive the AeadModes enumeration type-name from the formal string name
	/// </summary>
	/// 
	/// <param name="Name">The AeadModes string name</param>
	///
	/// <returns>The matching AeadModes enumeration type name</returns>
	static AeadModes FromName(std::string &Name);
};

NAMESPACE_ENUMERATIONEND
#endif
