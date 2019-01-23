#ifndef CEX_ECP_H
#define CEX_ECP_H

#include "IKdf.h"
#include "ProviderBase.h"

NAMESPACE_PROVIDER

using Kdf::IKdf;

/// <summary>
/// An implementation of a system Entropy Collector Provider.
/// <para>Note* This class has only been tested in Windows, other operating systems currently have limited support.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std::vector&lt;byte&gt; output(32);
/// ECP gen;
/// gen.Generate(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <para>The Entropy Collection Provider is a two stage entropy provider; it first collects system sources of entropy, and then uses them to initialize a block cipher CTR generator. \n 
/// The first stage collects numerous caches of low entropy states; high-resolution timers, process and thread ids, the system random provider, and statistics for various hardware devices and system operations. \n
/// These sources of entropy are compressed using Keccak to create a 512 bit cipher key. 
/// The key initializes an (HX extended) instance of Rijndael using 38 rounds and an HKDF(SHA512) key schedule. \n
/// The 16 byte counter and the HKDF distribution code (personalization string) are then created with the system entropy provider and used to initialize the cipher. \n
/// Output from the ECP provider is the product of encrypting the incrementing counter.
/// </para>
/// 
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">AES Fips 197</a>.</description></item>
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">The Keccak digest</a>.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>ANSI <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/rng/EntropySources.pdf">X9.82: </a>Entropy and Entropy Sources in X9.82.</description></item>
/// </list> 
/// </remarks>
class ECP final : public ProviderBase
{
private:

	static const std::string CLASS_NAME;
	static const size_t DEF_STATECAP = 1024;
	static const bool TIMER_HAS_TSC;

#if defined(CEX_FIPS140_ENABLED)
	ProviderSelfTest m_pvdSelfTest;
#endif
	std::unique_ptr<IKdf> m_kdfGenerator;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ECP(const ECP&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ECP& operator=(const ECP&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	ECP();

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~ECP() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	/// 
	/// <exception cref="CryptoRandomException">Thrown on entropy collection failure</exception>
	void Reset() override;

private:

	bool FipsTest();

	static std::vector<byte> Collect();
	static std::vector<byte> Compress(std::vector<byte> &State);
	static std::vector<byte> DriveInfo();
	static void Filter(std::vector<byte> &State);
	static void GetRandom(std::vector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IKdf> &Generator);
	static void GetRandom(SecureVector<byte> &Output, size_t Offset, size_t Length, std::unique_ptr<IKdf> &Generator);
	static std::vector<byte> MemoryInfo();
	static std::vector<byte> NetworkInfo();
	static std::vector<byte> ProcessInfo();
	static std::vector<byte> ProcessorInfo();
	static std::vector<byte> SystemInfo();
	static std::vector<byte> TimeInfo();
	static std::vector<byte> UserInfo();
};

NAMESPACE_PROVIDEREND
#endif
