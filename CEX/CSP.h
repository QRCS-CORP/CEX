#ifndef _CEX_CSP_H
#define _CEX_CSP_H

#include "IProvider.h"

NAMESPACE_PROVIDER

/// <summary>
/// An implementation of an entropy source provider using the system secure random generator.
/// <para>On a windows system, the RNGCryptoServiceProvider CryptGenRandom() function is used to generate output. 
/// On Android, the arc4random() function is used. All other systems (Linux, Unix), use dev/random.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std:vector&lt;uint8_t&gt; output(32);
/// CSP gen;
/// gen.GetBytes(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description>Microsoft <a href="http://msdn.microsoft.com/en-us/library/system.security.cryptography.rngcryptoserviceprovider.aspx">RNGCryptoServiceProvider</a>: class documentation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
/// </list> 
/// </remarks>
class CSP : public IProvider
{
private:

	bool m_isAvailable;

public:

	CSP(const CSP&) = delete;
	CSP& operator=(const CSP&) = delete;
	CSP& operator=(CSP&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The providers type name
	/// </summary>
	virtual const Enumeration::Providers Enumeral() { return Enumeration::Providers::CSP; }

	/// <summary>
	/// Get: The entropy provider is available on this system
	/// </summary>
	virtual const bool IsAvailable() { return m_isAvailable; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const std::string Name() { return "CSP"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class
	/// </summary>
	CSP();

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~CSP();

	//~~~Public Functions~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Fill a buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	virtual void GetBytes(std::vector<byte> &Output);

	/// <summary>
	/// Fill the buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	virtual void GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Return an array with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">The size of the expected array returned</param>
	/// 
	/// <returns>An array of pseudo-random of bytes</returns>
	virtual std::vector<byte> GetBytes(size_t Length);

	/// <summary>
	/// Returns a pseudo-random unsigned 32bit integer
	/// </summary>
	virtual uint32_t Next();

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();
};

NAMESPACE_PROVIDEREND
#endif
