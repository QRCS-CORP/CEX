#ifndef _CEXENGINE_ISO7816_H
#define _CEXENGINE_ISO7816_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The ISO7816 Padding Scheme
/// <para>ISO7816d as outlined in ISO/IEC 7816-4:2005: <see href="http://www.iso.org/iso/home/store/catalogue_tc/catalogue_detail.htm?csnumber=36134"/></para>
/// </summary>
class ISO7816 : public IPadding
{
private:
	const byte ZBCODE = (byte)0x00;
	const byte MKCODE = (byte)0x80;

public:
	// *** Constructor *** //

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	ISO7816() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~ISO7816() {}

	// *** Properties *** //

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	virtual const CEX::Enumeration::PaddingModes Enumeral() { return CEX::Enumeration::PaddingModes::ISO7816; }

	/// <summary>
	/// Get: Padding name
	/// </summary>
	virtual const char *Name() { return "ISO7816"; }

	// *** Public Methods *** //

	/// <summary>
	/// Add padding to input array
	/// </summary>
	///
	/// <param name="Input">Array to modify</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	///
	/// <exception cref="CEX::Exception::CryptoPaddingException">Thrown if the padding offset value is longer than the array length</exception>
	virtual unsigned int AddPadding(std::vector<byte> &Input, unsigned int Offset);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	virtual unsigned int GetPaddingLength(const std::vector<byte> &Input);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual unsigned int GetPaddingLength(const std::vector<byte> &Input, unsigned int Offset);
};

NAMESPACE_PADDINGEND
#endif

