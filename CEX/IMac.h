#ifndef _CEX_IMAC_H
#define _CEX_IMAC_H

#include "CexDomain.h"
#include "CryptoMacException.h"
#include "ISymmetricKey.h"
#include "Macs.h"
#include "SymmetricKeySize.h"

NAMESPACE_MAC

using Exception::CryptoMacException;
using Key::Symmetric::ISymmetricKey;
using Enumeration::Macs;
using Key::Symmetric::SymmetricKeySize;

/// <summary>
/// Message Authentication Code (MAC) Interface
/// </summary>
class IMac
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	IMac() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IMac() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Mac generators type name
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
	/// Get: Recommended Mac key sizes in a SymmetricKeySize array
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// Get: Mac generators class name
	/// </summary>
	virtual const std::string Name() = 0;

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
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

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
	/// Initialize the MAC generator with a SymmetricKey key container.
	/// <para>Uses a key and optional salt and info arrays to initialize the MAC.</para>
	/// </summary>
	/// 
	/// <param name="MacParam">A SymmetricKey key container class</param>
	virtual void Initialize(ISymmetricKey &MacParam) = 0;

	/// <summary>
	/// Initialize the MAC with a key
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	virtual void Initialize(const std::vector<byte> &Key) = 0;

	/// <summary>
	/// Initialize the MAC with a key and salt arrays
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	/// <param name="Salt">The salt or initialization vector</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt) = 0;

	/// <summary>
	/// Initialize the MAC generator.
	/// </summary>
	///
	/// <param name="Key">The MAC generators primary key</param>
	/// <param name="Salt">The salt or initialization vector</param>
	/// <param name="Info">The info parameter used as an addional source of entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info) = 0;

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
