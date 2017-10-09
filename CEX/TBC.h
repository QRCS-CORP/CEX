#ifndef CEX_TBC_H
#define CEX_TBC_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The Trailing Bit Compliment Padding Scheme
/// </summary>
class TBC final : public IPadding
{
private:

	TBC(const TBC&) = delete;
	TBC& operator=(const TBC&) = delete;
	TBC& operator=(TBC&&) = delete;

	static const std::string CLASS_NAME;
	static const byte MKCODE = (byte)0xFF;
	static const byte ZBCODE = (byte)0x00;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The padding modes type name
	/// </summary>
	const PaddingModes Enumeral() override;

	/// <summary>
	/// Get: The padding modes class name
	/// </summary>
	const std::string Name() override;

	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	TBC();

	/// <summary>
	/// Destructor
	/// </summary>
	~TBC() override;

	//~~~Public Functions~~~//

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
	size_t AddPadding(std::vector<byte> &Input, size_t Offset) override;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	///
	/// <returns>Length of padding</returns>
	size_t GetPaddingLength(const std::vector<byte> &Input) override;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">Padded array of bytes</param>
	/// <param name="Offset">Offset into array</param>
	///
	/// <returns>Length of padding</returns>
	size_t GetPaddingLength(const std::vector<byte> &Input, size_t Offset) override;
};

NAMESPACE_PADDINGEND
#endif
