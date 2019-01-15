#ifndef CEX_IPADDING_H
#define CEX_IPADDING_H

#include "CexDomain.h"
#include "CryptoPaddingException.h"
#include "ErrorCodes.h"
#include "PaddingModes.h"

NAMESPACE_PADDING

using Exception::CryptoPaddingException;
using Enumeration::PaddingModes; 
using Enumeration::ErrorCodes;

/// <summary>
/// Padding Mode Interface
/// </summary>
class IPadding
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IPadding(const IPadding&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IPadding& operator=(const IPadding&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IPadding() 
	{
	}

	/// <summary>
	/// Finalizer: Calls the default destructor
	/// </summary>
	virtual ~IPadding() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The padding modes type name
	/// </summary>
	virtual const PaddingModes Enumeral() = 0;

	/// <summary>
	/// Read Only: The padding modes class name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Add padding to an input array
	/// </summary>
	///
	/// <param name="Input">The array to modify</param>
	/// <param name="Offset">The starting offset in the array</param>
	/// <param name="Length">The number of bytes to pad</param>
	virtual void AddPadding(std::vector<byte> &Input, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">The padded array of bytes</param>
	///
	/// <returns>Returns the length of padding in bytes</returns>
	virtual size_t GetBlockLength(const std::vector<byte> &Input) = 0;

	/// <summary>
	/// Get the length of padding in an array using offset and length
	/// </summary>
	///
	/// <param name="Input">The padded array of bytes</param>
	/// <param name="Offset">The starting offset in the array</param>
	/// <param name="Length">The upper bound of bytes to check</param>
	///
	/// <returns>Returns the length of padding in bytes</returns>
	virtual size_t GetBlockLength(const std::vector<byte> &Input, size_t Offset, size_t Length) = 0;
};

NAMESPACE_PADDINGEND
#endif

