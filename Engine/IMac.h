#ifndef _CEXENGINE_IMAC_H
#define _CEXENGINE_IMAC_H

#include "Common.h"
#include "CryptoMacException.h"
#include "Macs.h"

NAMESPACE_MAC

using CEX::Exception::CryptoMacException;

/// <summary>
/// Message Authentication Code (MAC) Interface
/// </summary>
class IMac
{
public:
	// *** Constructor *** //

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	IMac() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IMac() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The macs type name
	/// </summary>
	virtual const CEX::Enumeration::Macs Enumeral() = 0;

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual const unsigned int BlockSize() = 0;

	/// <summary>
	/// Get: Size of returned mac in bytes
	/// </summary>
	virtual const unsigned int MacSize() = 0;

	/// <summary>
	/// Get: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() = 0;

	// *** Public Methods *** //

	/// <summary>
	/// Update the digest
	/// </summary>
	///
	/// <param name="Input">Hash input data</param>
	/// <param name="InOffset">Starting position with the Input array</param>
	/// <param name="Length">Length of data to process</param>
	virtual void BlockUpdate(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length) = 0;

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
	virtual unsigned int DoFinal(std::vector<byte> &Output, unsigned int OutOffset) = 0;

	/// <summary>
	/// Initialize the MAC generator.
	/// </summary>
	///
	/// <param name="KeyParam">The HMAC Key</param>
	virtual void Initialize(const std::vector<byte> &MacKey, std::vector<byte> &IV) = 0;

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
