#ifndef CEX_X923_H
#define CEX_X923_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The X.923 Padding Scheme
/// </summary>
class X923 final : public IPadding
{
private:

	static const std::string CLASS_NAME;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	X923(const X923&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	X923& operator=(const X923&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	X923();

	/// <summary>
	/// Destructor: finalize this class: finalize this class
	/// </summary>
	~X923() override;

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
	/// Add padding to an input array
	/// </summary>
	///
	/// <param name="Input">The array to modify</param>
	/// <param name="Offset">The Starting offset in the array</param>
	/// <param name="Length">The number of bytes to pad</param>
	///
	/// <exception cref="CryptoPaddingException">Thrown if the padding length is longer than the array length</exception>
	void AddPadding(std::vector<uint8_t> &Input, size_t Offset, size_t Length) override;

	/// <summary>
	/// Get the length of padding in an array
	/// </summary>
	///
	/// <param name="Input">The padded array of bytes</param>
	///
	/// <returns>Returns the length of padding in bytes</returns>
	size_t GetBlockLength(const std::vector<uint8_t> &Input) override;

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
	size_t GetBlockLength(const std::vector<uint8_t> &Input, size_t Offset, size_t Length) override;
};

NAMESPACE_PADDINGEND
#endif
