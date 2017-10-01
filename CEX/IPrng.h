#ifndef CEX_IPRNG_H
#define CEX_IPRNG_H

#include "CexDomain.h"
#include "CryptoRandomException.h"
#include "Prngs.h"

NAMESPACE_PRNG

using Exception::CryptoRandomException;
using Enumeration::Prngs;

/// <summary>
/// Psuedo Random Number Generator interface
/// </summary>
class IPrng
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// Initialize this class
	/// </summary>
	IPrng() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IPrng() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The random generators type name
	/// </summary>
	virtual const Prngs Enumeral() = 0;

	/// <summary>
	/// Get: The random generators class name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Fill an array of uint16 with pseudo-random
	/// </summary>
	///
	/// <param name="Output">The uint16 output array</param>
	/// <param name="Offset">The starting index within the Output array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	virtual void Fill(std::vector<ushort> &Output, size_t Offset, size_t Elements) = 0;

	/// <summary>
	/// Fill an array of uint32 with pseudo-random
	/// </summary>
	///
	/// <param name="Output">The uint32 output array</param>
	/// <param name="Offset">The starting index within the Output array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	virtual void Fill(std::vector<uint> &Output, size_t Offset, size_t Elements) = 0;

	/// <summary>
	/// Fill an array of uint64 with pseudo-random
	/// </summary>
	///
	/// <param name="Output">The uint64 output array</param>
	/// <param name="Offset">The starting index within the Output array</param>
	/// <param name="Elements">The number of array elements to fill</param>
	virtual void Fill(std::vector<ulong> &Output, size_t Offset, size_t Elements) = 0;

	/// <summary>
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Size">Size of requested byte array</param>
	/// 
	/// <returns>Random byte array</returns>
	virtual std::vector<byte> GetBytes(size_t Size) = 0;

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	virtual void GetBytes(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Get a pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	virtual ushort NextUShort() = 0;

	/// <summary>
	/// Get an pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	virtual ushort NextUShort(ushort Maximum) = 0;

	/// <summary>
	/// Get a pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt16</returns>
	virtual ushort NextUShort(ushort Maximum, ushort Minimum) = 0;

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt32</returns>
	virtual uint Next() = 0;

	/// <summary>
	/// Get an pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	virtual uint Next(uint Maximum) = 0;

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	virtual uint Next(uint Maximum, uint Minimum) = 0;

	/// <summary>
	/// Get a pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt64</returns>
	virtual ulong NextULong() = 0;

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	virtual ulong NextULong(ulong Maximum) = 0;

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// <param name="Minimum">Minimum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	virtual ulong NextULong(ulong Maximum, ulong Minimum) = 0;

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_PRNGEND
#endif