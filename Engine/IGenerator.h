#ifndef _CEXENGINE_IGenerator_H
#define _CEXENGINE_IGenerator_H

#include "Common.h"
#include "CryptoGeneratorException.h"
#include "Generators.h"

NAMESPACE_GENERATOR

using CEX::Exception::CryptoGeneratorException;

/// <summary>
/// Pseudo random Generator Interface
/// </summary>
class IGenerator
{
public:
	// *** Constructor *** //

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	IGenerator() {}

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	virtual ~IGenerator() {}


	// *** Properties *** //

	/// <summary>
	/// Get: The generators type name
	/// </summary>
	virtual const CEX::Enumeration::Generators Enumeral() = 0;

	/// <summary>
	/// Get: Generator is ready to produce data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// <para>Minimum initialization key size in bytes; 
	/// combined sizes of Salt, Ikm, and Nonce must be at least this size.</para>
	/// </summary>
	virtual size_t KeySize() = 0;

	/// <summary>
	/// Algorithm name
	/// </summary>
	virtual const char *Name() = 0;

	// *** Public Methods *** //

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
	/// <returns>Number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output) = 0;

	/// <summary>
	/// Generate pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Output array filled with random bytes</param>
	/// <param name="OutOffset">The starting position within Output array</param>
	/// <param name="Size">Number of bytes to generate</param>
	/// 
	/// <returns>Number of bytes generated</returns>
	virtual size_t Generate(std::vector<byte> &Output, size_t OutOffset, size_t Size) = 0;

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value</param>
	virtual void Initialize(const std::vector<byte> &Salt) = 0;

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value</param>
	/// <param name="Ikm">Key material</param>
	virtual void Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm) = 0;

	/// <summary>
	/// Initialize the generator
	/// </summary>
	/// 
	/// <param name="Salt">Salt value</param>
	/// <param name="Ikm">Key material</param>
	/// <param name="Nonce">Nonce value</param>
	virtual void Initialize(const std::vector<byte> &Salt, const std::vector<byte> &Ikm, const std::vector<byte> &Nonce) = 0;

	/// <summary>
	/// Update the Seed material
	/// </summary>
	/// 
	/// <param name="Salt">Pseudo random seed material</param>
	virtual void Update(const std::vector<byte> &Salt) = 0;
};

NAMESPACE_GENERATOREND
#endif
