#ifndef _CEXENGINE_IPADDING_H
#define _CEXENGINE_IPADDING_H

#include "Common.h"
#include "CryptoPaddingException.h"
#include "PaddingModes.h"

NAMESPACE_PADDING

using CEX::Exception::CryptoPaddingException;

/// <summary>
/// Padding Mode Interface
/// </summary>
class IPadding
{
public:
	// *** Constructor *** //

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	IPadding() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IPadding() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	virtual const CEX::Enumeration::PaddingModes Enumeral() = 0;

	/// <summary>
	/// Get: Padding name
	/// </summary>
	virtual const char *Name() = 0;

	// *** Public Methods *** //

	/// <summary>
	/// Add padding to input array
	/// </summary>
	///
	/// <param name="Input">Array to modify</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual unsigned int AddPadding(std::vector<byte> &Input, unsigned int Offset) = 0;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	virtual unsigned int GetPaddingLength(const std::vector<byte> &Input) = 0;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual unsigned int GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset) = 0;
};

NAMESPACE_PADDINGEND
#endif

