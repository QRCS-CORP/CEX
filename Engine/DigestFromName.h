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
	static CEX::Digest::IDigest* GetInstance(CEX::Enumeration::Digests DigestType);

	/// <summary>
	/// Get the input block size of a message digest
	/// </summary>
	/// 
	/// <param name="DigestType">The Digest enumeration member</param>
	/// 
	/// <returns>The block size in bytes</returns>
	static int GetBlockSize(CEX::Enumeration::Digests DigestType);

	/// <summary>
	/// Get the hash size of a message digest
	/// </summary>
	/// 
	/// <param name="DigestType">The Digest enumeration member</param>
	/// 
	/// <returns>The hash size size in bytes</returns>
	static int GetDigestSize(CEX::Enumeration::Digests DigestType);
};

NAMESPACE_HELPEREND
#endif