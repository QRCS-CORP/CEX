#ifndef CEX_HKDSMESSAGES_H
#define CEX_HKDSMESSAGES_H

#include "CexDomain.h"

NAMESPACE_ENUMERATION

/// <summary>
/// HKDS message types
/// </summary>
enum class HkdsMessages : byte
{
	/// <summary>
	/// No message type is specified
	/// </summary>
	None = 0,
	/// <summary>
	/// 
	/// </summary>
	MessageRequest = 1,
	/// <summary>
	/// 
	/// </summary>
	MessageResponse = 2,
	/// <summary>
	/// 
	/// </summary>
	TokenRequest = 3,
	/// <summary>
	/// 
	/// </summary>
	TokenResponse = 4,
	/// <summary>
	/// 
	/// </summary>
	TokenReceived = 5,
};

NAMESPACE_ENUMERATIONEND
#endif
