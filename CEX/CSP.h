#ifndef CEX_CSP_H
#define CEX_CSP_H

#include "ProviderBase.h"

NAMESPACE_PROVIDER

/// <summary>
/// An implementation of an entropy source provider using the system secure random generator.
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std::vector&lt;byte&gt; output(32);
/// CSP gen;
/// gen.Generate(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <para>On a windows system, the RNGCryptoServiceProvider CryptGenRandom() function is used to generate output. 
/// On Android, the arc4random() function is used. All other systems (Linux, Unix), use dev/random.</para>
///
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description>Microsoft <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</a>: class documentation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
/// </list> 
/// </remarks>
class CSP final : public ProviderBase
{
private:

	static const std::string CLASS_NAME;

#if defined(CEX_FIPS140_ENABLED)
	ProviderSelfTest m_pvdSelfTest;
#endif

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CSP(const CSP&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CSP& operator=(const CSP&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	CSP();

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CSP() override;

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill the buffer with pseudo-random bytes using offsets
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output SecureVector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill the SecureVector with pseudo-random bytes using offsets
	/// </summary>
	///
	/// <param name="Output">The output SecureVector to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	void Reset() override;

private:

	bool FipsTest();
	static void GetEntropy(byte* Output, size_t Length);
};

NAMESPACE_PROVIDEREND
#endif
