#ifndef _CEX_PKCS7_H
#define _CEX_PKCS7_H

#include "IPadding.h"

NAMESPACE_PADDING

/// <summary>
/// The PKCS7 Padding Scheme
/// </summary>
/// 
/// <remarks>
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>RFC <a href="http://tools.ietf.org/html/rfc5652">5652</a>.</description></item>
/// </list>
/// </remarks>
class PKCS7 final : public IPadding
{
private:

	PKCS7(const PKCS7&) = delete;
	PKCS7& operator=(const PKCS7&) = delete;
	PKCS7& operator=(PKCS7&&) = delete;

	static const std::string CLASS_NAME;

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
	PKCS7();

	/// <summary>
	/// Destructor
	/// </summary>
	~PKCS7() override;

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
