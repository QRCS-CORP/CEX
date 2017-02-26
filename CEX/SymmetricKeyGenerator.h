#ifndef _CEX_KEYGENERATOR_H
#define _CEX_KEYGENERATOR_H

#include "CexDomain.h"
#include "CryptoGeneratorException.h"
#include "Digests.h"
#include "IProvider.h"
#include "Providers.h"
#include "SymmetricKey.h"
#include "SymmetricKeySize.h"
#include "SymmetricSecureKey.h"

NAMESPACE_KEYSYMMETRIC

using Exception::CryptoGeneratorException;
using Enumeration::Digests;
using Enumeration::Providers;
using Symmetric::SymmetricKey;
using Symmetric::SymmetricKeySize;
using Symmetric::SymmetricSecureKey;

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

	SymmetricKeyGenerator(const SymmetricKeyGenerator&) = delete;
	SymmetricKeyGenerator& operator=(const SymmetricKeyGenerator&) = delete;
	SymmetricKeyGenerator& operator=(SymmetricKeyGenerator&&) = delete;

	Digests m_dgtType;
	bool m_isDestroyed;
	Providers m_pvdType;
	Provider::IProvider* m_pvdEngine;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class.
	/// <para>Select provider and digest type generator options, or take the defaults</para>
	/// </summary>
	/// 
	/// <param name="DigestType">The hash function used to power an hmac used to condition output keying material</param>
	/// <param name="ProviderType">The entropy provider that supplies the seed material for the key compression cycle</param>
	SymmetricKeyGenerator(Digests DigestType = Digests::SHA512, Providers ProviderType = Enumeration::Providers::CSP);

	/// <summary>
	/// Destructor
	/// </summary>
	~SymmetricKeyGenerator();

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	void Destroy();

	/// <summary>
	/// Create a populated SymmetricKey class
	/// </summary>
	/// 
	/// <param name="KeySize">The key, nonce and info sizes in bytes to generate</param>
	/// 
	/// <returns>A populated SymmetricKey class</returns>
	SymmetricKey GetSymmetricKey(SymmetricKeySize KeySize);

	/// <summary>
	/// Create a populated SymmetricKey class
	/// </summary>
	/// 
	/// <param name="KeySize">The key, nonce and info sizes in bytes to generate</param>
	/// 
	/// <returns>A populated SymmetricSecureKey class</returns>
	SymmetricSecureKey GetSecureKey(SymmetricKeySize KeySize);

	/// <summary>
	/// Fill an array with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Output">Array to fill with random bytes</param>
	void GetBytes(std::vector<byte> &Output);

	/// <summary>
	/// Return an array filled with pseudo random bytes
	/// </summary>
	/// 
	/// <param name="Size">Size of requested byte array</param>
	/// 
	/// <returns>Pseudo random byte array</returns>
	std::vector<byte> GetBytes(size_t Size);

	/// <summary>
	/// Reset the seed Seed Generators and the Digest engine
	/// </summary>
	void Reset();

private:

	std::vector<byte> Generate(size_t KeySize);
	std::vector<byte> GenerateBlock();
};

NAMESPACE_KEYSYMMETRICEND
#endif
