#ifndef _CEXENGINE_DIGESTFROMNAME_H
#define _CEXENGINE_DIGESTFROMNAME_H

#include "Common.h"
#include "CryptoException.h"
#include "IDigest.h"

NAMESPACE_HELPER

/// <summary>
/// DigestFromName: Get a Message Digest instance from it's enumeration name.
/// </summary>
class DigestFromName
{
public:
	/// <summary>
	/// Get a Digest instance by name
	/// </summary>
	/// 
	/// <param name="DigestType">The message digest enumeration name</param>
	/// 
	/// <returns>An initialized digest</returns>
	/// 
	/// <exception cref="CEX::Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static  CEX::Digest::IDigest* GetInstance(CEX::Enumeration::Digests DigestType);
};

NAMESPACE_HELPEREND
#endif