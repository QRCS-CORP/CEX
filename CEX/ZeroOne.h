#ifndef CEX_ZEROPAD_H
#define CEX_ZEROPAD_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The Zero Padding Scheme (Not Recommended).
/// </summary>
class ZeroOne final : public IPadding
{
private:

	static const std::string CLASS_NAME;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ZeroOne(const ZeroOne&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ZeroOne& operator=(const ZeroOne&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	ZeroOne();

	/// <summary>
	/// Destructor: finalize this class: finalize this class
	/// </summary>
	~ZeroOne() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The padding modes type name
	/// </summary>
	const PaddingModes Enumeral() override;

	/// <summary>
	/// Read Only: The padding modes class name
	/// </summary>
	const std::string Name() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Add padding to input array
	/// </summary>
	///
	/// <param name="Input">Array to modify</param>
	/// <param name="Offset">Offset into array</param>
	/// <param name="Length">The number of bytes to pad</param>
	///
	/// <exception cref="CryptoPaddingException">Thrown if the padding length is longer than the array length</exception>
	void AddPadding(std::vector<byte> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">The padded array of bytes</param>
	///
	/// <returns>Returns the length of padding in bytes</returns>
	size_t GetBlockLength(const std::vector<byte> &Input) override;

	/// <summary>
	/// Get the length of padding in an array using offset and length
	/// </summary>
	///
	/// <param name="Input">The padded array of bytes</param>
	/// <param name="Offset">The starting offset in the array</param>
	/// <param name="Length">The upper bound of bytes to check</param>
	///
	/// <returns>Returns the length of padding in bytes</returns>
	///
	/// <exception cref="CryptoPaddingException">Thrown if the length is longer than the array length</exception>
	size_t GetBlockLength(const std::vector<byte> &Input, size_t Offset, size_t Length) override;
};

NAMESPACE_PADDINGEND
#endif

