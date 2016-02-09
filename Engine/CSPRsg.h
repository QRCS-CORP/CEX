#ifndef _CEXENGINE_CSPRSG_H
#define _CEXENGINE_CSPRSG_H

#include "ISeed.h"

#ifdef _WIN32
#include <Windows.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/types.h>
#include <thread>
#endif

NAMESPACE_SEED

/// <summary>
/// CSPRsg: An implementation of a Cryptographically Secure seed generator using the RNGCryptoServiceProvider class
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// CSPRsg gen;
/// gen.GetSeed(Output);
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
class CSPRsg : public ISeed
{
private:
#ifdef _WIN32
	HCRYPTPROV _hProvider = 0;
#endif

public:
	// *** Properties *** //

	/// <summary>
	/// Get: The seed generators type name
	/// </summary>
	virtual const CEX::Enumeration::SeedGenerators Enumeral() { return CEX::Enumeration::SeedGenerators::CSPRsg; }

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() { return "CSPRsg"; }

	// *** Constructor *** //

	/// <summary>
	/// Initialize this class
	/// </summary>
	CSPRsg()
	{
		Reset();
	}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~CSPRsg()
	{
		Destroy();
	}

	// *** Public Methods *** //

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Fill the buffer with random bytes
	/// </summary>
	///
	/// <param name="Output">The array to fill</param>
	virtual void GetBytes(std::vector<byte> &Output);

	/// <summary>
	/// Get a pseudo random seed byte array
	/// </summary>
	/// 
	/// <param name="Size">The size of the expected seed returned</param>
	/// 
	/// <returns>A pseudo random seed</returns>
	virtual std::vector<byte> GetBytes(int Size);

	/// <summary>
	/// Returns the next pseudo random 32bit integer
	/// </summary>
	virtual int Next();

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();
};

NAMESPACE_SEEDEND
#endif
