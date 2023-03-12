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
/// <para>Generates an array, or a SymmetricKey or SymmetricSecureKey container class, using a definable cSHAKE-xxx(Provider+cutomization) generator.</para>
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

	Providers m_providerType;
	SecurityPolicy m_securityPolicy;

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
	/// Instantiate the SymmetricKeyGenerator class with seurity policy and provider enumeration names
	/// </summary>
	/// 
	/// <param name="Policy">The security policy, defines expected strength of internal primitives</param>
	/// <param name="ProviderType">The entropy provider, supplies the seed material for the pseudo-random generator</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if an invalid parameter is used</exception>
	SymmetricKeyGenerator(SecurityPolicy Policy = SecurityPolicy::SPL512, Providers ProviderType = Providers::ACP);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~SymmetricKeyGenerator();

	//~~~Accesors~~~//

	/// <summary>
	/// Read Only: The underlying generators formal class name
	/// </summary>
	const std::string Name();

	//~~~Public Functions~~~//

	/// <summary>
	/// Create a SymmetricKey populated with pseudo-random secure vectors
	/// </summary>
	/// 
	/// <param name="KeySize">The SymmetricKeySize class, containing the key, nonce, and info sizes in bytes</param>
	/// 
	/// <returns>A SymmetricKey class populated with pseudo-random data</returns>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key size is zero length</exception>
	SymmetricKey* GetSymmetricKey(SymmetricKeySize KeySize);

	/// <summary>
	/// Create a SymmetricSecureKey populated with encrypted pseudo-random secure vectors
	/// </summary>
	/// 
	/// <param name="KeySize">The SymmetricKeySize class, containing the key, nonce, and info sizes in bytes</param>
	/// 
	/// <returns>A SymmetricSecureKey class populated with pseudo-random data</returns>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the key size is zero length</exception>
	SymmetricSecureKey* GetSecureKey(SymmetricKeySize KeySize);

	/// <summary>
	/// Fill a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Output">The secure-vector to fill with pseudo-random bytes</param>
	/// <param name="Offset">The starting offset within the output uint8_t vector</param>
	/// <param name="Length">The length of the requested pseudo-random bytes allocation</param>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the request size is zero length or the output array is too small</exception>
	void Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Return a secure-vector with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">The length of the requested pseudo-random bytes allocation</param>
	/// 
	/// <returns>A secure-vector filled with pseudo-random bytes</returns>
	/// 
	/// <exception cref="CryptoGeneratorException">Thrown if the request size is zero length</exception>
	SecureVector<uint8_t> Generate(size_t Length);

private:

	static void Generate(Providers Provider, SecurityPolicy Policy, SecureVector<uint8_t> &Output, size_t Offset, size_t Length);
};

NAMESPACE_CIPHEREND
#endif
