#ifndef CEX_ISO7816_H
#define CEX_ISO7816_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The ESP Padding Scheme
/// </summary>
class ESP final : public IPadding
{
private:

	static const std::string CLASS_NAME;
	static const byte MKCODE = 0x80;
	static const byte ZBCODE = 0x00;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ESP(const ESP&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ESP& operator=(const ESP&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	ESP();

	/// <summary>
	/// Destructor: finalize this class: finalize this class
	/// </summary>
	~ESP() override;

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

