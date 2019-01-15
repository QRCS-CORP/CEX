#ifndef CEX_IPRNG_H
#define CEX_IPRNG_H

#include "CexDomain.h"
#include "CryptoRandomException.h"
#include "Prngs.h"

NAMESPACE_PRNG

using Exception::CryptoRandomException;
using Enumeration::ErrorCodes;
using Enumeration::Prngs;

/// <summary>
/// Psuedo Random Number Generator interface
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
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Length">Size of requested byte array</param>
	/// 
	/// <returns>Random byte array</returns>
	virtual std::vector<byte> Generate(size_t Length) = 0;

	/// <summary>
	/// Fill the buffer with pseudo-random bytes using offsets
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	virtual void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	virtual void Generate(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Get a pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	virtual ushort NextUInt16() = 0;

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt32</returns>
	virtual uint NextUInt32() = 0;

	/// <summary>
	/// Get a pseudo random unsigned 64bit integer
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
