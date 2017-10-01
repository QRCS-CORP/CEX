#ifndef CEX_ACP_H
#define CEX_ACP_H

#include "IProvider.h"
#include "ICipherMode.h"

NAMESPACE_PROVIDER

/// <summary>
/// An implementation of an Auto Collection seed Provider
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std:vector&lt;byte&gt; output(32);
/// ACP gen;
/// gen.GetBytes(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <para>The Auto Collection Provider is a two stage entropy provider; it first collects system sources of entropy, and then uses them to initialize a block cipher CTR generator. \n 
/// The first stage combines RdRand, cpu/memory jitter, and the system random provider, with high resolution timers and statistics for various hardware devices and system operations. \n
/// These sources of entropy are compressed using Keccak to create a 512 bit cipher key. 
/// The key initializes an (HX extended) instance of Rijndael using 38 rounds and an HKDF(SHA512) key schedule. \n
/// The 16 byte counter and the HKDF distribution code (personalization string) are then created with the system entropy provider. \n
/// Output from the ACP provider is the product of encrypting the incrementing counter.
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
class ACP : public IProvider
{
private:

	static const std::string CLASS_NAME;
	static const size_t DEF_STATECAP = 1024;

	Cipher::Symmetric::Block::Mode::ICipherMode* m_cipherMode;
	bool m_hasTsc;
	bool m_hasRdrand;
	bool m_isAvailable;

public:

	ACP(const ACP&) = delete;
	ACP& operator=(const ACP&) = delete;
	ACP& operator=(ACP&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The providers type name
	/// </summary>
	const Providers Enumeral() override;

	/// <summary>
	/// Get: The entropy provider is available on this system
	/// </summary>
	const bool IsAvailable() override;

	/// <summary>
	/// Get: The provider class name
	/// </summary>
	const std::string Name() override;

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class
	/// </summary>
	ACP();

	/// <summary>
	/// Destructor
	/// </summary>
	~ACP() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object; optional, called by the finalizer
	/// </summary>
	void Destroy() override;

	/// <summary>
	/// Fill a buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	void GetBytes(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill the buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	void GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Return an array with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">The size of the expected array returned</param>
	/// 
	/// <returns>An array of pseudo-random of bytes</returns>
	std::vector<byte> GetBytes(size_t Length) override;

	/// <summary>
	/// Returns a pseudo-random unsigned 32bit integer
	/// </summary>
	uint Next() override;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	void Reset() override;

private:

	std::vector<byte> Collect();
	std::vector<byte> ACP::Compress(std::vector<byte> &State);
	void Filter(std::vector<byte> &State);
	std::vector<byte> MemoryInfo();
	std::vector<byte> ProcessInfo();
	void Scope();
	std::vector<byte> SystemInfo();
	std::vector<byte> TimeInfo();
};

NAMESPACE_PROVIDEREND
#endif
