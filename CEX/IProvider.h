#ifndef CEX_IPROVIDER_H
#define CEX_IPROVIDER_H

#include "CexDomain.h"
#include "CryptoRandomException.h"
#include "Providers.h"
#include "SecureVector.h"

NAMESPACE_PROVIDER

using Exception::CryptoRandomException;
using Enumeration::ErrorCodes;
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
	/// Fill a standard vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	virtual void Generate(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	virtual void Generate(SecureVector<byte> &Output) = 0;

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	virtual void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	virtual void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Get a pseudo-random unsigned 16bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	virtual ushort NextUInt16() = 0;

	/// <summary>
	/// Get a pseudo-random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt32</returns>
	virtual uint NextUInt32() = 0;

	/// <summary>
	/// Get a pseudo-random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt64</returns>
	virtual ulong NextUInt64() = 0;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_PROVIDEREND
#endif

