#ifndef _CEXENGINE_ISEED_H
#define _CEXENGINE_ISEED_H

#include "Common.h"
#include "CryptoRandomException.h"
#include "SeedGenerators.h"

NAMESPACE_SEED

using CEX::Exception::CryptoRandomException;

/// <summary>
/// ISeed: Pseudo random seed generator interface
/// </summary>
class ISeed
{
public:
	// *** Constructor *** //

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	ISeed() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~ISeed() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The seed generators type name
	/// </summary>
	virtual const CEX::Enumeration::SeedGenerators Enumeral() = 0;

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
	/// Get the pseudo random bytes
	/// </summary>
	///
	/// <param name="Output">Output array</param>
	virtual void GetBytes(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Get a pseudo random seed byte array
	/// </summary>
	/// 
	/// <param name="Size">The size of the expected seed returned</param>
	/// 
	/// <returns>A pseudo random seed</returns>
	virtual std::vector<byte> GetBytes(size_t Size) = 0;

	/// <summary>
	/// Returns the next pseudo random 32bit integer
	/// </summary>
	virtual int Next() = 0;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_SEEDEND
#endif

