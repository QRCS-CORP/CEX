#ifndef CEX_PROVIDERSELFTEST_H
#define CEX_PROVIDERSELFTEST_H

#include "CexDomain.h"
#include "Providers.h"
#include "SecureVector.h"

NAMESPACE_PROVIDER

using Enumeration::Providers;

/// <summary>
/// The continuous test required by FIPS 140-2; the function automatically primes the test if needed
/// </summary>
class ProviderSelfTest
{
public:

	static const size_t SELFTEST_LENGTH = sizeof(uint64_t);
	SecureVector<uint8_t> m_rndSample;

	ProviderSelfTest();

	~ProviderSelfTest();

	/// <summary>
	/// Test a new sample against one stored for repeating output
	/// </summary>
	///
	/// <param name="Sample">The SecureVector random sample</param>
	bool SelfTest(SecureVector<uint8_t> &Sample);
};

NAMESPACE_PROVIDEREND
#endif
