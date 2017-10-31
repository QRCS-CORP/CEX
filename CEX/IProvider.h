#ifndef CEX_IPROVIDER_H
#define CEX_IPROVIDER_H

#include "CexDomain.h"
#include "CryptoRandomException.h"
#include "Providers.h"

NAMESPACE_PROVIDER

using Exception::CryptoRandomException;
using Enumeration::Providers;

/// <summary>
/// Entropy source collectors and concentrators interface
/// </summary>
class IProvider
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IProvider(const IProvider&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IProvider& operator=(const IProvider&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IProvider() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IProvider() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The providers type name
	/// </summary>
	virtual const Providers Enumeral() = 0;

	/// <summary>
	/// Read Only: The entropy provider is available on this system
	/// </summary>
	virtual const bool IsAvailable() = 0;

	/// <summary>
	/// Read Only: The provider class name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	virtual void GetBytes(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Fill the buffer with pseudo-random bytes using offsets
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	virtual void GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Return an array with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">The size of the expected array returned</param>
	/// 
	/// <returns>An array of pseudo-random of bytes</returns>
	virtual std::vector<byte> GetBytes(size_t Length) = 0;

	/// <summary>
	/// Returns a pseudo-random unsigned 32bit integer
	/// </summary>
	virtual uint Next() = 0;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_PROVIDEREND
#endif

