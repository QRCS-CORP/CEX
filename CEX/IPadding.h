#ifndef CEX_IPADDING_H
#define CEX_IPADDING_H

#include "CexDomain.h"
#include "CryptoPaddingException.h"
#include "PaddingModes.h"

NAMESPACE_PADDING

using Enumeration::PaddingModes;
using Exception::CryptoPaddingException;

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
	/// Add padding to input array
	/// </summary>
	///
	/// <param name="Input">Array to modify</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual size_t AddPadding(std::vector<byte> &Input, size_t Offset) = 0;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	virtual size_t GetPaddingLength(const std::vector<byte> &Input) = 0;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual size_t GetPaddingLength(const std::vector<byte> &Input, size_t Offset) = 0;
};

NAMESPACE_PADDINGEND
#endif

