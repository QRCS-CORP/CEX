#ifndef CEX_SYMMETRICKEYGENERATOR_H
#define CEX_SYMMETRICKEYGENERATOR_H

#include "CexDomain.h"
#include "CryptoGeneratorException.h"
#include "Digests.h"
#include "IProvider.h"
#include "Providers.h"
#include "SymmetricKey.h"
#include "SymmetricKeySize.h"
#include "SymmetricSecureKey.h"

NAMESPACE_SYMMETRICKEY

using Exception::CryptoGeneratorException;
using Enumeration::Digests;
using Enumeration::Providers;

/// <summary>
/// A helper class for generating cryptographically strong keying material.
/// <para>Generates an array, or an SymmetricKey or SymmetricSecureKey container class, using a definable Mac(Provider()) dual stage generator.
/// The first stage of the generator gets seed material from the entropy provider, then Macs the seed and adds the result to the output key array.</para>
/// </summary>
/// 
/// <example>
/// <description>Generate a symmetric key:</description>
/// <code>
/// SymmetricKeyGenerator gen([Digests], [Providers]);
/// // keysize with a 256 bit key and a 128 bit initialization vector
/// SymmetricKeySize ks(32, 16, 0);
/// // generate a symmetric key
/// SymmetricKey key = gen.GetKey(ks);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Seed provider can be any of the <see cref="Enumeration::Providers"/> generators.</description></item>
/// <item><description>Hash can be any of the <see cref="Enumeration::Digests"/> digests.</description></item>
/// <item><description>Default Prng is CSP, default digest is SHA512.</description></item>
/// </list>
/// </remarks>
class SymmetricKeyGenerator
{
private:

	Digests m_dgtType;
	bool m_isDestroyed;
	Providers m_pvdType;
	std::unique_ptr<Provider::IProvider> m_pvdEngine;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	SymmetricKeyGenerator(const SymmetricKeyGenerator&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	SymmetricKeyGenerator& operator=(const SymmetricKeyGenerator&) = delete;

	/// <summary>
	/// Constructor: instantiate this class.
	/// <para>Select provider and digest type generator options, or take the defaults</para>
	/// </summary>
	/// 
	/// <param name="DigestType">The hash function used to power an hmac used to condition output keying material</param>
	/// <param name="ProviderType">The entropy provider that supplies the seed material for the key compression cycle</param>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if an invalid parameter is used</exception>
	explicit SymmetricKeyGenerator(Digests DigestType = Digests::SHA512, Providers ProviderType = Enumeration::Providers::CSP);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SymmetricKeyGenerator();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a populated SymmetricKey class
	/// </summary>
	/// 
	/// <param name="KeySize">The key, nonce and info sizes in bytes to generate</param>
	/// 
	/// <returns>A populated SymmetricKey class</returns>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the key size is zero length</exception>
	SymmetricKey* GetSymmetricKey(SymmetricKeySize KeySize);

	/// <summary>
	/// Create a populated SymmetricKey class
	/// </summary>
	/// 
	/// <param name="Length">The key, nonce, and info sizes in bytes to generate</param>
	/// 
	/// <returns>A populated SymmetricSecureKey class</returns>
	/// 
	/// <exception cref="Exception::CryptoGeneratorException">Thrown if the key size is zero length</exception>
	SymmetricSecureKey* GetSecureKey(SymmetricKeySize Length);

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Array to fill with random bytes</param>
	void Generate(std::vector<byte> &Output);

	/// <summary>
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Length">Size of requested byte array</param>
	/// 
	/// <returns>Pseudo random byte array</returns>
	std::vector<byte> Generate(size_t Length);

	/// <summary>
	/// Reset the seed Seed Generators and the Digest engine
	/// </summary>
	void Reset();

private:

	void Destroy();
	std::vector<byte> Process(size_t KeySize);
	std::vector<byte> ProcessBlock();
};

NAMESPACE_SYMMETRICKEYEND
#endif
