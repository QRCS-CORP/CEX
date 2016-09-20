#ifndef _CEXENGINE_IDIGEST_H
#define _CEXENGINE_IDIGEST_H

#include "Common.h"
#include "Digests.h"
#include "MacParams.h"
#if defined(CPPEXCEPTIONS_ENABLED)
#	include "CryptoDigestException.h"
#endif

NAMESPACE_DIGEST

using CEX::Enumeration::Digests;
using CEX::Common::MacParams;
#if defined(CPPEXCEPTIONS_ENABLED)
	using CEX::Exception::CryptoDigestException;
#endif

/// <summary>
/// Hash Digest Interface
/// </summary>
class IDigest
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	IDigest() {}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~IDigest() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Digests internal block size in bytes
	/// </summary>
	virtual size_t BlockSize() = 0;

	/// <summary>
	/// Get: Size of returned hash value in bytes
	/// </summary>
	virtual size_t DigestSize() = 0;

	/// <summary>
	/// Get: The digests type enumeration member
	/// </summary>
	virtual Digests Enumeral() = 0;

	/// <summary>
	/// Get: The Digest name
	/// </summary>
	virtual const char *Name() = 0;

	//~~~Public Methods~~~//

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length) = 0;

	/// <summary>
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The hash output value array</param>
	virtual void ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Do final processing and get the hash value
	/// </summary>
	/// 
	/// <param name="Output">The Hash output value array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <returns>Size of Hash value</returns>
	virtual size_t DoFinal(std::vector<byte> &Output, const size_t OutOffset) = 0;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input) = 0;
};

NAMESPACE_DIGESTEND
#endif

