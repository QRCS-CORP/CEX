#ifndef CEX_IDRBG_H
#define CEX_IDRBG_H

#include "CexDomain.h"
#include "CryptoGeneratorException.h"
#include "Drbgs.h"
#include "IProvider.h"
#include "ISymmetricKey.h"
#include "Providers.h"
#include "SecureVector.h"
#include "SymmetricKey.h"
#include "SymmetricKeySize.h"
#include "SymmetricSecureKey.h"

NAMESPACE_DRBG

using Exception::CryptoGeneratorException;
using Enumeration::Drbgs;
using Enumeration::ErrorCodes;
using Provider::IProvider;
using Cipher::ISymmetricKey;
using Enumeration::Providers;
using Cipher::SymmetricKey;
using Cipher::SymmetricKeySize;
using Cipher::SymmetricSecureKey;

/// <summary>
/// The DRBG virtual interface class.
/// <para>This class can be used to create functions that will accept any of the implemented DRBG instances as a parameter.</para>
/// </summary>
class IDrbg
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IDrbg(const IDrbg&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IDrbg& operator=(const IDrbg&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	IDrbg() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IDrbg() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The Drbg generators type name
	/// </summary>
	virtual const Drbgs Enumeral() = 0;

	/// <summary>
	/// Read Only: Generator is ready to produce random
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: List of available legal key sizes
	/// </summary>
	virtual const std::vector<SymmetricKeySize> LegalKeySizes() = 0;

	/// <summary>
	/// Read Only: The maximum number of bytes that can be generated with a generator instance
	/// </summary>
	virtual const ulong MaxOutputSize() = 0;

	/// <summary>
	/// Read Only: The maximum number of bytes that can be generated in a single request
	/// </summary>
	virtual const size_t MaxRequestSize() = 0;

	/// <summary>
	/// Read Only: The maximum number of times the generator can be reseeded
	/// </summary>
	virtual const size_t MaxReseedCount() = 0;

	/// <summary>
	/// The Drbg generators class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read/Write: The maximum output generated between auto-seed generation when using an entropy provider
	/// </summary>
	virtual size_t &ReseedThreshold() = 0;

	/// <summary>
	/// Read Only: The security strength in bits
	/// </summary>
	virtual const size_t SecurityStrength() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector to fill with random bytes</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	virtual void Generate(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector to fill with random bytes</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	virtual void Generate(SecureVector<byte> &Output) = 0;

	/// <summary>
	/// Fill a standard-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector to fill with random bytes</param>
	/// <param name="OutOffset">The starting position within the output vector</param>
	/// <param name="Length">The number of bytes to generate</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	virtual void Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length) = 0;

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector to fill with random bytes</param>
	/// <param name="OutOffset">The starting position within the output vector</param>
	/// <param name="Length">The number of bytes to generate</param>
	///
	/// <exception cref="CryptoGeneratorException">Thrown if the generator is not initialized, the output size is misaligned, 
	/// the maximum request size is exceeded, or if the maximum reseed requests are exceeded</exception>
	virtual void Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length) = 0;

	/// <summary>
	/// Initialize the generator with a SymmetricKey structure containing the key and optional salt (Nonce) and info string (Info)
	/// </summary>
	/// 
	/// <param name="Parameters">The SymmetricKey containing the generators keying material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the seed is not a legal seed size</exception>
	virtual void Initialize(ISymmetricKey &Parameters) = 0;

	/// <summary>
	/// Update the generators keying material
	/// </summary>
	///
	/// <param name="Key">The new seed value array</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the seed is too small</exception>
	virtual void Update(const std::vector<byte> &Key) = 0;

	/// <summary>
	/// Update the generators keying material with a secure-vector key
	/// </summary>
	///
	/// <param name="Key">The secure-vector containing the new key material</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key is too small</exception>
	virtual void Update(const SecureVector<byte> &Key) = 0;

};

NAMESPACE_DRBGEND
#endif
