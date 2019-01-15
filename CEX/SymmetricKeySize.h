#ifndef CEX_SYMMETRICKEYSIZE_H
#define CEX_SYMMETRICKEYSIZE_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"

NAMESPACE_CIPHER

using Exception::CryptoProcessingException;

/// <summary>
/// Contains key and vector sizes
/// </summary> 
struct SymmetricKeySize
{
private:

	static const size_t HDR_SIZE = sizeof(uint) * 3;

	uint m_infoSize;
	uint m_keySize;
	uint m_nonceSize;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the default structure
	/// </summary>
	SymmetricKeySize();

	/// <summary>
	/// Initialize this structure using a serialized byte array
	/// </summary>
	/// 
	/// <param name="KeyArray">Key byte array containing a serialized SymmetricKeySize structure</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if the key array is too small</exception>
	explicit SymmetricKeySize(const std::vector<byte> &KeyArray);

	/// <summary>
	/// Initialize this structure with parameters
	/// </summary>
	/// 
	/// <param name="KeySize">The key byte array length</param>
	/// <param name="NonceSize">The nonce byte array length</param>
	/// <param name="InfoSize">The info byte array length</param>
	SymmetricKeySize(size_t KeySize, size_t NonceSize, size_t InfoSize);

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: The info byte array length
	/// </summary>
	const uint InfoSize();

	/// <summary>
	/// Read/Write: The key byte array length
	/// </summary>
	const uint KeySize();

	/// <summary>
	/// Read/Write: The nonce byte array length
	/// </summary>
	const uint NonceSize();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a clone of this structure
	/// </summary>
	SymmetricKeySize Clone();

	/// <summary>
	/// Test a SymmetricKeySize array for specific values
	/// </summary>
	/// 
	/// <param name="SymmetricKeySizes">An array of legal SymmetricKeySizes</param>
	/// <param name="KeySize">The key byte length</param>
	/// <param name="NonceSize">The nonce byte length</param>
	/// <param name="InfoSize">The info byte length</param>
	/// 
	/// <returns>True if the SymmetricKeySize array contains the values</returns>
	static bool Contains(std::vector<SymmetricKeySize> SymmetricKeySizes, size_t KeySize, size_t NonceSize = 0, size_t InfoSize = 0);

	/// <summary>
	/// Create a deep copy of this structure.
	/// <para>Caller must delete this object.</para>
	/// </summary>
	/// 
	/// <returns>A pointer to a SymmetricKeySize instance</returns>
	SymmetricKeySize* DeepCopy();

	/// <summary>
	/// Compare this object instance with another
	/// </summary>
	/// 
	/// <param name="Input">Object to compare</param>
	/// 
	/// <returns>True if equal, otherwise false</returns>
	bool Equals(SymmetricKeySize &Input);

	/// <summary>
	/// Get the hash code for this object
	/// </summary>
	/// 
	/// <returns>Hash code</returns>
	uint GetHashCode();

	/// <summary>
	/// Get the header size in bytes
	/// </summary>
	/// 
	/// <returns>Header size</returns>
	static size_t GetHeaderSize();

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
