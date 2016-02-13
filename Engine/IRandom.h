#ifndef _CEXENGINE_IRANDOM_H
#define _CEXENGINE_IRANDOM_H

#include "Common.h"
#include "CryptoRandomException.h"
#include "Prngs.h"

NAMESPACE_PRNG

using CEX::Exception::CryptoRandomException;

/// <summary>
/// Psuedo Random Number Generator interface
/// </summary>
class IRandom
{
public:
	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	IRandom() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IRandom() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The prngs type name
	/// </summary>
	virtual const CEX::Enumeration::Prngs Enumeral() = 0;

	/// <summary>
	/// Get: Algorithm name
	/// </summary>
	virtual const char *Name() = 0;

	// *** Public Methods *** //

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

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
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt32</returns>
	virtual uint Next(uint Minimum, uint Maximum) = 0;

	/// <summary>
	/// Get a pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt64</returns>
	virtual ulong NextLong() = 0;

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	virtual ulong NextLong(ulong Maximum) = 0;

	/// <summary>
	/// Get a ranged pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <param name="Minimum">Minimum value</param>
	/// <param name="Maximum">Maximum value</param>
	/// 
	/// <returns>Random UInt64</returns>
	virtual ulong NextLong(ulong Minimum, ulong Maximum) = 0;

	/// <summary>
	/// Reset the generator instance
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_PRNGEND
#endif