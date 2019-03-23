#ifndef CEX_IPRNG_H
#define CEX_IPRNG_H

#include "CexDomain.h"
#include "CryptoRandomException.h"
#include "Prngs.h"
#include "SecureVector.h"

NAMESPACE_PRNG

using Exception::CryptoRandomException;
using Enumeration::ErrorCodes;
using Enumeration::Prngs;

/// <summary>
/// The PRNG virtual interface class.
/// <para>This class can be used to create functions that will accept any of the implemented PRNG instances as a parameter.</para>
/// </summary>
class IPrng
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IPrng(const IPrng&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IPrng& operator=(const IPrng&) = delete;

	/// <summary>
	/// Initialize this class
	/// </summary>
	IPrng() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IPrng() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The random generators type name
	/// </summary>
	virtual const Prngs Enumeral() = 0;

	/// <summary>
	/// Read Only: The random generators class name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	virtual void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Fill a SecureVector array with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	virtual void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	virtual void Generate(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Fill a SecureVector array with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard-vector to fill</param>
	virtual void Generate(SecureVector<byte> &Output) = 0;

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
	/// Reset the generator instance
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_PRNGEND
#endif
