#ifndef CEX_DIGESTFROMNAME_H
#define CEX_DIGESTFROMNAME_H

#include "CexDomain.h"
#include "CryptoException.h"
#include "IDigest.h"

NAMESPACE_HELPER

using Enumeration::Digests;
using Digest::IDigest;

/// <summary>
/// Get a Message Digest instance from it's enumeration name.
/// </summary>
class DigestFromName
{
public:
	/// <summary>
	/// Get a Digest instance by name
	/// </summary>
	/// 
	/// <param name="DigestType">The message digests enumeration type name</param>
	/// <param name="Parallel">Return the digest instance initialized in parallel mode; default is false</param>
	/// 
	/// <returns>An initialized digest</returns>
	/// 
	/// <exception cref="Exception::CryptoException">Thrown if the enumeration name is not supported</exception>
	static IDigest* GetInstance(Digests DigestType, bool Parallel = false);

	/// <summary>
	/// Get the input block size of a message digest
	/// </summary>
	/// 
	/// <param name="DigestType">The message digests enumeration type name</param>
	/// 
	/// <returns>The block in bytes</returns>
	static size_t GetBlockSize(Digests DigestType);

	/// <summary>
	/// Get the hash size of a message digest
	/// </summary>
	/// 
	/// <param name="DigestType">The Digest enumeration member</param>
	/// 
	/// <returns>The hash size in bytes</returns>
	static size_t GetDigestSize(Digests DigestType);


	/// <summary>
	/// Get the size of internal padding applied to the last block during the hash finalizer
	/// </summary>
	/// 
	/// <param name="DigestType">The Digest enumeration member</param>
	/// 
	/// <returns>The padding size size in bytes</returns>
	static size_t GetPaddingSize(Digests DigestType);
};

NAMESPACE_HELPEREND
#endif