#ifndef CEX_IKDF_H
#define CEX_IKDF_H

#include "CexDomain.h"
#include "CryptoKdfException.h"
#include "ISymmetricKey.h"
#include "Kdfs.h"
#include "SecureVector.h"
#include "SymmetricKey.h"
#include "SymmetricKeySize.h"

NAMESPACE_KDF

using Enumeration::ErrorCodes;
using Enumeration::Kdfs;
using Cipher::ISymmetricKey;
using Exception::CryptoKdfException;
using Cipher::SymmetricKey;
using Cipher::SymmetricKeySize;

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
	/// Read Only: The KDF generators type name
	/// </summary>
	virtual const Enumeration::Kdfs Enumeral() = 0;

	/// <summary>
	/// Read Only: Generator is initialized and ready to produce pseudo-random
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: Minimum recommended initialization key size in bytes
	/// </summary>
	virtual const size_t MinimumKeySize() = 0;

	/// <summary>
	/// Read Only: Minimum recommended salt size in bytes
	/// </summary>
	virtual const size_t MinimumSaltSize() = 0;

	/// <summary>
	/// Read Only: Available KDF Key Sizes in SymmetricKeySize containers
	/// </summary>
	virtual const std::vector<SymmetricKeySize> LegalKeySizes() = 0;

	/// <summary>
	/// The KDF generators formal class name
	/// </summary>
	virtual const std::string Name() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	virtual void Generate(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	virtual void Generate(SecureVector<byte> &Output) = 0;

	/// <summary>
	/// Fill an array with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination standard-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	virtual void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes, using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The destination secure-vector to fill</param>
	/// <param name="Offset">The starting position within the destination array</param>
	/// <param name="Length">The number of bytes to generate</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the maximum request size is exceeded</exception>
	virtual void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Initialize the generator with a SymmetricKey or SecureSymmetricKey; containing the key, and optional salt, and info string
	/// </summary>
	/// 
	/// <param name="Parameters">The symmetric key container with the generators keying material</param>
	/// 
	/// <exception cref="CryptoKdfException">Thrown if the key values are not a legal size</exception>
	virtual void Initialize(ISymmetricKey &Parameters) = 0;

	/// <summary>
	/// Reset the internal state; the generator must be re-initialized before it can be used again
	/// </summary>
	virtual void Reset() = 0;
};

NAMESPACE_KDFEND
#endif
