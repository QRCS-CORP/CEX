#ifndef _CEX_ISO7816_H
#define _CEX_ISO7816_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The ISO7816 Padding Scheme
/// </summary>
///
/// <remarks>
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>ISO/IEC <a href="http://www.iso.org/iso/home/store/catalogue_tc/catalogue_detail.htm?csnumber=36134">7816-4:2005</a>.</description></item>
/// </list>
/// </remarks>
class ISO7816 : public IPadding
{
private:

	ISO7816(const ISO7816&) = delete;
	ISO7816& operator=(const ISO7816&) = delete;
	ISO7816& operator=(ISO7816&&) = delete;

	const byte ZBCODE = (byte)0x00;
	const byte MKCODE = (byte)0x80;

public:
	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	ISO7816() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~ISO7816() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	virtual const PaddingModes Enumeral() { return PaddingModes::ISO7816; }

	/// <summary>
	/// Get: The padding modes class name
	/// </summary>
	virtual const std::string Name() { return "ISO7816"; }

	//~~~Public Methods~~~//

	/// <summary>
	/// Add padding to input array
	/// </summary>
	///
	/// <param name="Input">Array to modify</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	///
	/// <exception cref="Exception::CryptoPaddingException">Thrown if the padding offset value is longer than the array length</exception>
	virtual size_t AddPadding(std::vector<byte> &Input, size_t Offset);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	virtual size_t GetPaddingLength(const std::vector<byte> &Input);

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	virtual size_t GetPaddingLength(const std::vector<byte> &Input, size_t Offset);
};

NAMESPACE_PADDINGEND
#endif

