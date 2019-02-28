#ifndef CEX_SYMMETRICKEYSIZE_H
#define CEX_SYMMETRICKEYSIZE_H

#include "CexDomain.h"
#include "CryptoSymmetricException.h"

NAMESPACE_CIPHER

using Exception::CryptoSymmetricException;

/// <summary>
/// Contains the legal byte lengths for SymmetricKey and SymmetricSecureKey pseudo-random keying material
/// </summary> 
struct SymmetricKeySize
{
private:

	static const std::string CLASS_NAME;

	size_t m_infoSize;
	size_t m_keySize;
	size_t m_nonceSize;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the default structure
	/// </summary>
	SymmetricKeySize();

	/// <summary>
	/// Initialize this structure using a serialized SymmetricKeySize vector
	/// </summary>
	/// 
	/// <param name="KeyArray">Array containing a serialized SymmetricKeySize structure</param>
	/// 
	/// <exception cref="CryptoSymmetricException">Thrown if the key array is too small</exception>
	explicit SymmetricKeySize(const std::vector<byte> &KeyArray);

	/// <summary>
	/// Initialize this structure with parameters
	/// </summary>
	/// 
	/// <param name="KeySize">The key parameters byte length</param>
	/// <param name="NonceSize">The nonce parameters byte length</param>
	/// <param name="InfoSize">The info parameters byte length</param>
	SymmetricKeySize(size_t KeySize, size_t NonceSize, size_t InfoSize);

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: The info parameters length in bytes
	/// </summary>
	const size_t InfoSize();

	/// <summary>
	/// Read/Write: The key parameters length in bytes
	/// </summary>
	const size_t KeySize();

	/// <summary>
	/// Read/Write: The nonce parameters length in bytes
	/// </summary>
	const size_t NonceSize();

	//~~~Public Functions~~~//

	/// <summary>
	/// Test a SymmetricKeySize array for specific values
	/// </summary>
	/// 
	/// <param name="SymmetricKeySizes">A vector of SymmetricKeySizes</param>
	/// <param name="KeySize">The key length to check</param>
	/// <param name="NonceSize">The nonce length to check</param>
	/// <param name="InfoSize">The info length to check</param>
	/// 
	/// <returns>Returns true if the SymmetricKeySize array contains the values</returns>
	static bool Contains(std::vector<SymmetricKeySize> SymmetricKeySizes, size_t KeySize, size_t NonceSize = 0, size_t InfoSize = 0);

	/// <summary>
	/// Set all struct members to defaults
	/// </summary>
	void Reset();

	/// <summary>
	/// Convert the SymmetricKeySize structure serialized to a byte array
	/// </summary>
	/// 
	/// <returns>The byte array containing the SymmetricKeySize</returns>
	std::vector<byte> ToBytes();
};

NAMESPACE_CIPHEREND
#endif
