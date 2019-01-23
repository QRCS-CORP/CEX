#ifndef CEX_SYMMETRICKEYGENERATOR_H
#define CEX_SYMMETRICKEYGENERATOR_H

#include "CexDomain.h"
#include "CryptoGeneratorException.h"
#include "Digests.h"
#include "Providers.h"
#include "SecurityPolicy.h"
#include "SymmetricKey.h"
#include "SymmetricKeySize.h"
#include "SymmetricSecureKey.h"

NAMESPACE_CIPHER

using Exception::CryptoGeneratorException;
using Enumeration::Digests;
using Enumeration::Providers;
using Enumeration::SecurityPolicy;

/// <summary>
/// A helper class for generating cryptographically strong keying material.
/// <para>Generates an array, or an SymmetricKey or SymmetricSecureKey container class, using a definable cSHAKE(Provider+cutomization) generator.</para>
/// </summary>
/// 
/// <example>
/// <description>Generate a symmetric key:</description>
/// <code>
/// SymmetricKeyGenerator gen([SecurityPolicy], [Providers]);
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
/// <item><description>Seed provider can be any of the <see cref="Enumeration::Providers"/> random providers.</description></item>
/// <item><description>The SecurityPolicy determines the expected cryptographic strength of the pseudo-random output (256. 512, or 1024)</description></item>
/// </list>
/// </remarks>
class SymmetricKeyGenerator
{
private:

	static const std::string CLASS_NAME;
	static const std::vector<byte> SIGMA_INFO;

	bool m_isDestroyed;
	Providers m_pvdType;
	SecurityPolicy m_secPolicy;
	std::vector<byte> m_shakeCustom;

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
	/// Instantiate this class.
	/// <para>Uses the implementation default customization array to implement cSHAKE.</para>
	/// </summary>
	/// 
	/// <param name="Policy">The security policy, controls expected strength of internal used primitives</param>
	/// <param name="ProviderType">The entropy provider, supplies the seed material for the pseudo-random generator</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if an invalid parameter is used</exception>
	SymmetricKeyGenerator(SecurityPolicy Policy= SecurityPolicy::SPL512, Providers ProviderType = Providers::ACP);

	/// <summary>
	/// Instantiate this class.
	/// <para>Specify a user provided salt value to create a custom cSHAKE generator.</para>
	/// </summary>
	/// 
	/// <param name="Policy">The security policy, controls expected strength of internal used primitives</param>
	/// <param name="Customization">The non-default cSHAKE customization array; this can be used to add additional entropy to the generator sequence</param>
	/// <param name="ProviderType">The entropy provider, supplies the seed material for the pseudo-random generator</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if an invalid parameter is used</exception>
	SymmetricKeyGenerator(SecurityPolicy Policy, const std::vector<byte> &Customization, Providers ProviderType = Providers::ACP);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SymmetricKeyGenerator();

	//~~~Accesors~~~//

	/// <summary>
	/// Read Only: The underlying generators primitive names
	/// </summary>
	const std::string Name();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a populated SymmetricKey class
	/// </summary>
	/// 
	/// <param name="KeySize">The key, nonce and info sizes in bytes to generate</param>
	/// 
	/// <returns>A populated SymmetricKey class</returns>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key size is zero length</exception>
	SymmetricKey* GetSymmetricKey(SymmetricKeySize KeySize);

	/// <summary>
	/// Create a populated SymmetricKey class
	/// </summary>
	/// 
	/// <param name="KeySize">The key, nonce, and info sizes in bytes to generate</param>
	/// 
	/// <returns>A populated SymmetricSecureKey class</returns>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key size is zero length</exception>
	SymmetricSecureKey* GetSecureKey(SymmetricKeySize KeySize);

	/// <summary>
	/// Fill an array with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The array to fill with random bytes</param>
	/// <param name="Offset">The starting offset within the output byte array</param>
	/// <param name="Length">The size of requested byte array</param>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Return an array filled with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">Size of requested byte array</param>
	/// 
	/// <returns>Pseudo random byte array</returns>
	std::vector<byte> Generate(size_t Length);

private:

	static void Generate(Providers Provider, SecurityPolicy Policy, const std::vector<byte> &Salt, std::vector<byte> &Output, size_t Offset, size_t Length);
};

NAMESPACE_CIPHEREND
#endif
