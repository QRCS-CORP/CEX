#include "ProviderSelfTest.h"
#include "MemoryTools.h"

NAMESPACE_PROVIDER

using Tools::MemoryTools;

//~~~Constructor~~~//

ProviderSelfTest::ProviderSelfTest()
	:
	m_rndSample(SELFTEST_LENGTH)
{
}

ProviderSelfTest::~ProviderSelfTest()
{
	MemoryTools::Clear(m_rndSample, 0, SELFTEST_LENGTH);
}

//~~~Public Functions~~~//

bool ProviderSelfTest::SelfTest(SecureVector<uint8_t> &Sample)
{
	uint64_t rl1;
	uint64_t rl2;
	bool fail;

	rl1 = 0;
	rl2 = 0;

	MemoryTools::CopyToValue(m_rndSample, 0, rl1, SELFTEST_LENGTH);
	MemoryTools::CopyToValue(Sample, 0, rl2, SELFTEST_LENGTH);

	if (rl1 == rl2)
	{
		fail = true;
	}
	else
	{
		fail = false;
	}

	MemoryTools::Clear(m_rndSample, 0, SELFTEST_LENGTH);
	MemoryTools::Copy(Sample, 0, m_rndSample, 0, SELFTEST_LENGTH);
	MemoryTools::Clear(Sample, 0, SELFTEST_LENGTH);

	return (fail == false);
}

NAMESPACE_PROVIDEREND
