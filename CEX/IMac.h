#ifndef CEX_IMAC_H
#define CEX_IMAC_H

#include "CexDomain.h"
#include "CryptoMacException.h"
#include "ErrorCodes.h"
#include "ISymmetricKey.h"
#include "Macs.h"
#include "SecureVector.h"
#include "SymmetricKeySize.h"

NAMESPACE_MAC

using Exception::CryptoMacException;
using Enumeration::ErrorCodes;
using Cipher::ISymmetricKey;
using Enumeration::Macs;
using Cipher::SymmetricKeySize;


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
	/// Read Only: The MACs internal blocksize in bytes
	/// </summary>
	virtual const size_t BlockSize() = 0;

	/// <summary>
	/// Read Only: The MAC generator is ready to process data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: Recommended MAC key sizes in a SymmetricKeySize array
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// Read Only: Minimum allowed initialization key-size in bytes
	/// </summary>
	virtual const size_t MinimumKeySize() = 0;

	/// <summary>
	/// Read Only: Minimum allowed initialization salt-size in bytes
	/// </summary>
	virtual const size_t MinimumSaltSize() = 0;

	/// <summary>
	/// Read Only: MAC generators formal class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: The size of the output MAC code in bytes
	/// </summary>
	virtual const size_t TagSize() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Process a vector of bytes and return the MAC code
	/// </summary>
	///
	/// <param name="Input">The input vector to process</param>
	/// <param name="Output">The output vector containing the MAC code</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Completes processing and returns the MAC code in a standard vector
	/// </summary>
	///
	/// <param name="Output">The output standard vector receiving the MAC code</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	///
	/// <returns>The size of the MAC code in bytes</returns>
	virtual size_t Finalize(std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Completes processing and returns the MAC code in a secure vector
	/// </summary>
	///
	/// <param name="Output">The output secure vector receiving the MAC code</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	///
	/// <returns>The size of the MAC code in bytes</returns>
	virtual size_t Finalize(SecureVector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Initialize the MAC generator with an ISymmetricKey key container.
	/// <para>Can accept either the SymmetricKey or SymmetricSecureKey container to load keying material.
	/// Uses a key, and optional salt and info arrays to initialize the MAC.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">An ISymmetricKey key interface, which can accept either a SymmetricKey or SymmetricSecureKey container</param>
	virtual void Initialize(ISymmetricKey &KeyParams) = 0;

	/// <summary>
	/// Reset internal state to the pre-initialization defaults.
	/// <para>Internal state is zeroised, and MAC generator must be reinitialized again before being used.</para>
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Update the Mac with a length of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input data vector to process</param>
	/// <param name="InOffset">The starting position with the input array</param>
	/// <param name="Length">The length of data to process in bytes</param>
	virtual void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) = 0;
};

NAMESPACE_MACEND
#endif
