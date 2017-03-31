#ifndef _CEX_IDRBG_H
#define _CEX_IDRBG_H

#include "CexDomain.h"
#include "CryptoGeneratorException.h"
#include "Drbgs.h"
#include "IProvider.h"
#include "ISymmetricKey.h"
#include "Providers.h"
#include "SymmetricKeySize.h"

NAMESPACE_DRBG

using Exception::CryptoGeneratorException;
using Enumeration::Drbgs;
using Provider::IProvider;
using Key::Symmetric::ISymmetricKey;
using Enumeration::Providers;
using Key::Symmetric::SymmetricKeySize;

/// <summary>
/// Deterministic Random Byte Generator (DRBG) interface class
/// </summary>
class IDrbg
{
public:
	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate the class and internal state
	/// </summary>
	IDrbg() {}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~IDrbg() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Drbg generators type name
	/// </summary>
	virtual const Drbgs Enumeral() = 0;

	/// <summary>
	/// Get: Generator is ready to produce random
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get: List of available legal key sizes
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// Get: The maximum number of bytes that can be generated with a generator instance
	/// </summary>
	virtual const ulong MaxOutputSize() = 0;

	/// <summary>
	/// Get: The maximum number of bytes that can be generated in a single request
	/// </summary>
	virtual const size_t MaxRequestSize() = 0;

	/// <summary>
	/// Get: The maximum number of times the generator can be reseeded
	/// </summary>
	virtual const size_t MaxReseedCount() = 0;

	/// <summary>
	/// The Drbg generators class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Get: The size of the nonce counter value in bytes
	/// </summary>
	virtual const size_t NonceSize() = 0;

	/// <summary>
	/// Get/Set: The maximum output generated between seed recycling
	/// </summary>
	virtual size_t &ReseedThreshold() = 0;

	/// <summary>
	/// Get: The security strength in bits
	/// </summary>
	virtual const size_t SecurityStrength() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

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
	virtual void Update(const std::vector<byte> &Seed) = 0;
};

NAMESPACE_DRBGEND
#endif
