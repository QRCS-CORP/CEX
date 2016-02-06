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
/// CSPRsg: Operating system pseudo random provider.
/// <para>On a windows system uses the CryptGenRandom api, otherwise uses calls to arc4random.</para>
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
/// <revisionHistory>
/// <revision date="2015/06/09" version="1.0.0.0">Initial release</revision>
/// </revisionHistory>
class CSPRsg : public ISeed
{
protected:
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
	/// <param name="Input">The array to fill</param>
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
