#ifndef CEX_IMAC_H
#define CEX_IMAC_H

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
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IMac(const IMac&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IMac& operator=(const IMac&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IMac() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IMac() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Mac generators type name
	/// </summary>
	virtual const Macs Enumeral() = 0;

	/// <summary>
	/// Read Only: The Digests internal blocksize in bytes
	/// </summary>
	virtual const size_t BlockSize() = 0;

	/// <summary>
	/// Read Only: Size of returned mac in bytes
	/// </summary>
	virtual const size_t MacSize() = 0;

	/// <summary>
	/// Read Only: Mac is ready to digest data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: Recommended Mac key sizes in a SymmetricKeySize array
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// Read Only: Mac generators class name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Get the MAC value
	/// </summary>
	///
	/// <param name="Input">Input data</param>
	/// <param name="Output">The output Mac code</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Completes processing and returns the HMAC code
	/// </summary>
	///
	/// <param name="Output">Output array that receives the hash code</param>
	/// <param name="OutOffset">Offset within Output array</param>
	///
	/// <returns>The number of bytes processed</returns>
	virtual size_t Finalize(std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Initialize the MAC generator with a SymmetricKey key container.
	/// <para>Uses a key and optional salt and info arrays to initialize the MAC.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey key container class</param>
	virtual void Initialize(ISymmetricKey &KeyParams) = 0;

	/// <summary>
	/// Reset to the default state; Mac code and buffer are zeroised, but key is still loaded
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Update the Mac with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte to process</param>
	virtual void Update(byte Input) = 0;

	/// <summary>
	/// Update the Mac with a block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input data array to process</param>
	/// <param name="InOffset">Starting position with the input array</param>
	/// <param name="Length">The length of data to process in bytes</param>
	virtual void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) = 0;
};

NAMESPACE_MACEND
#endif
