#ifndef CEX_IKDF_H
#define CEX_IKDF_H

#include "CexDomain.h"
#include "CryptoKdfException.h"
#include "ISymmetricKey.h"
#include "Kdfs.h"
#include "SymmetricKeySize.h"

NAMESPACE_KDF

using Enumeration::Kdfs;
using Key::Symmetric::ISymmetricKey;
using Exception::CryptoKdfException;
using Key::Symmetric::SymmetricKeySize;

/// <summary>
/// Key Derivation Function (KDF) interface class
/// </summary>
class IKdf
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IKdf(const IKdf&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IKdf& operator=(const IKdf&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	IKdf() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IKdf() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Kdf generators type name
	/// </summary>
	virtual const Enumeration::Kdfs Enumeral() = 0;

	/// <summary>
	/// Read Only: Generator is ready to produce random
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Minimum recommended initialization key size in bytes.
	/// <para>Combined sizes of key, salt, and info should be at least this size.</para>
	/// </summary>
	virtual const size_t MinKeySize() = 0;

	/// <summary>
	/// Read Only: List of available legal key sizes
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// The Kdf generators class name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Generate a block of pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Generate pseudo random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <returns>The number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) = 0;

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key and optional salt (Nonce) and info string (Info)
	/// </summary>
	/// 
	/// <param name="GenParam">The SymmetricKey containing the generators keying material</param>
	virtual void Initialize(ISymmetricKey &GenParam) = 0;

	/// <summary>
	/// Initialize the generator with a key
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	virtual void Initialize(const std::vector<byte> &Key) = 0;

	/// <summary>
	/// Initialize the generator with a key, using length and offset arguments
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Offset">The starting position within the key array</param>
	/// <param name="Length">The number of key bytes to use</param>
	/// 
	/// <exception cref="Exception::CryptoKdfException">Thrown if the key is too small</exception>
	virtual void Initialize(const std::vector<byte> &Key, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Initialize the generator with key and salt arrays
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value containing an additional source of entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt) = 0;

	/// <summary>
	/// Initialize the generator with a key, a salt array, and an information string or nonce
	/// </summary>
	/// 
	/// <param name="Key">The primary key array used to seed the generator</param>
	/// <param name="Salt">The salt value used as an additional source of entropy</param>
	/// <param name="Info">The information string or nonce used as a third source of entropy</param>
	virtual void Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info) = 0;

	/// <summary>
	/// Update the generators keying material
	/// </summary>
	///
	/// <param name="Seed">The new seed value array</param>
	virtual void ReSeed(const std::vector<byte> &Seed) = 0;

	/// <summary>
	/// Reset the internal state; Kdf must be re-initialized before it can be used again
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_KDFEND
#endif
