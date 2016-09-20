#ifndef _CEXENGINE_IMAC_H
#define _CEXENGINE_IMAC_H

#include "Common.h"
#include "Macs.h"
#if defined(CPPEXCEPTIONS_ENABLED)
#	include "CryptoMacException.h"
#endif

NAMESPACE_MAC

using CEX::Enumeration::Macs;
#if defined(CPPEXCEPTIONS_ENABLED)
	using CEX::Exception::CryptoMacException;
#endif

/// <summary>
/// Message Authentication Code (MAC) Interface
/// </summary>
class IMac
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	IMac() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IMac() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The macs type name
	/// </summary>
	virtual const Macs Enumeral() = 0;

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual const size_t BlockSize() = 0;

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const size_t MacSize() = 0;

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() = 0;

	//~~~Public Methods~~~//

	/// <summary>
	/// Update the digest
	/// </summary>
	///
	/// <param name="Input">Hash input data</param>
	/// <param name="InOffset">Starting position with the Input array</param>
	/// <param name="Length">Length of data to process</param>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length) = 0;

	/// <summary>
	/// Get the MAC value
	/// </summary>
	///
	/// <param name="Input">Input data</param>
	/// <param name="Output">The output Mac code</param>
	virtual void ComputeMac(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Completes processing and returns the HMAC code
	/// </summary>
	///
	/// <param name="Output">Output array that receives the hash code</param>
	/// <param name="OutOffset">Offset within Output array</param>
	///
	/// <returns>The number of bytes processed</returns>
	virtual size_t DoFinal(std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Initialize the MAC generator.
	/// </summary>
	///
	/// <param name="MacKey">The HMAC Key</param>
	/// <param name="IV">The optional IV</param>
	virtual void Initialize(const std::vector<byte> &MacKey, const std::vector<byte> &IV) = 0;

	/// <summary>
	/// Reset and initialize the underlying digest
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Update the digest with 1 byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input) = 0;
};

NAMESPACE_MACEND
#endif
