#include "RDP.h"
#include "CpuDetect.h"
#include "Intrinsics.h"
#include "IntegerTools.h"

NAMESPACE_PROVIDER

using Tools::IntegerTools;
using Enumeration::ProviderConvert;

//~~~Constructor~~~//

RDP::RDP(DrandEngines DrandType)
	:
#if defined(CEX_FIPS140_ENABLED)
	m_pvdSelfTest(new ProviderSelfTest),
#endif
	ProviderBase(Capability() != DrandEngines::None, Providers::RDP, ProviderConvert::ToName(Providers::RDP)),
	m_randType(DrandType == DrandEngines::RdSeed ? Capability() :
		DrandType == DrandEngines::RdRand ? 
			DrandType :
			throw CryptoRandomException(ProviderConvert::ToName(Providers::RDP), std::string("Constructor"), std::string("Random provider type can not be None!"), ErrorCodes::IllegalOperation))
{
}

RDP::~RDP()
{
	if (m_pvdSelfTest != nullptr)
	{
		m_pvdSelfTest.reset(nullptr);
	}

	m_randType = DrandEngines::None;
}

//~~~Public Functions~~~//

void RDP::Generate(std::vector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (m_randType == DrandEngines::RdSeed && Output.size() > SEED_MAX)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::IllegalOperation);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(Output.data(), Output.size(), m_randType);
}

void RDP::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (m_randType == DrandEngines::RdSeed && Output.size() > SEED_MAX)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::IllegalOperation);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(&Output[Offset], Length, m_randType);
}

void RDP::Generate(SecureVector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (m_randType == DrandEngines::RdSeed && Output.size() > SEED_MAX)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::IllegalOperation);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(Output.data(), Output.size(), m_randType);
}

void RDP::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (m_randType == DrandEngines::RdSeed && Output.size() > SEED_MAX)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::IllegalOperation);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(&Output[Offset], Length, m_randType);
}

void RDP::Reset()
{
}

//~~~Private Functions~~~//

DrandEngines RDP::Capability()
{
	DrandEngines eng;

#if defined(CEX_AVX_INTRINSICS)
	CpuDetect dtc;

	if (dtc.RDSEED())
	{
		eng = DrandEngines::RdSeed;
	}
	else if (dtc.RDRAND())
	{
		eng = DrandEngines::RdRand;
	}
	else
	{
		eng = DrandEngines::None;
	}
#else
	eng = DrandEngines::None;
#endif

	return eng;
}

//~~~Private Functions~~~//

bool RDP::FipsTest()
{
	bool fail;

	fail = false;

#if defined(CEX_FIPS140_ENABLED)

	SecureVector<uint8_t> smp(m_pvdSelfTest->SELFTEST_LENGTH);

	Generate(smp.data(), smp.size(), m_randType);

	if (!m_pvdSelfTest->SelfTest(smp))
	{
		fail = true;
	}

#endif

	return (fail == false);
}

void RDP::Generate(uint8_t* Output, size_t Length, DrandEngines DrandType)
{
	size_t fctr;
	size_t i;
	size_t poff;
	int32_t res;

#if defined(CEX_AVX_INTRINSICS)

	fctr = 0;
	poff = 0;
	res = 0;

#	if defined(CEX_IS_X64)

	uint64_t rnd64;

	while (Length != 0)
	{
		rnd64 = 0;

		if (DrandType == DrandEngines::RdSeed)
		{
			res = _rdseed64_step(&rnd64);
		}
		else
		{
			res = _rdrand64_step(&rnd64);
		}

		if (res == RDR_SUCCESS)
		{
			const size_t RMDLEN = IntegerTools::Min(sizeof(uint64_t), Length);

			for (i = 0; i < RMDLEN; ++i)
			{
				Output[poff + i] = static_cast<uint8_t>(rnd64 >> (i * 8));
			}

			poff += RMDLEN;
			Length -= RMDLEN;
			fctr = 0;
		}
		else
		{
			++fctr;

			if ((DrandType == DrandEngines::RdRand && fctr >= RDR_RETRY) || fctr >= RDS_RETRY)
			{
				throw CryptoRandomException(ProviderConvert::ToName(Providers::RDP), std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::MaxExceeded);
			}
		}
	}

#	else

	uint32_t rnd32;

	while (Length != 0)
	{
		rnd32 = 0;

		if (DrandType == DrandEngines::RdSeed)
		{
			res = _rdseed32_step(&rnd32);
		}
		else
		{
			res = _rdrand32_step(&rnd32);
		}

		if (res == RDR_SUCCESS)
		{
			const size_t RMDLEN = IntegerTools::Min(sizeof(uint32_t), Length);

			for (i = 0; i < RMDLEN; ++i)
			{
				Output[poff + i] = static_cast<uint8_t>(rnd32 >> (i * 8));
			}

			poff += RMDLEN;
			Length -= RMDLEN;
			fctr = 0;
		}
		else
		{
			++fctr;

			if ((DrandType == DrandEngines::RdRand && fctr >= RDR_RETRY) || fctr >= RDS_RETRY)
			{
				throw CryptoRandomException(ProviderConvert::ToName(Providers::RDP), std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::MaxExceeded);
			}
		}
	}
#	endif

#else

	throw CryptoRandomException(ProviderConvert::ToName(Providers::RDP), std::string("Generate"), std::string("AVX is not available on this system!"), ErrorCodes::NotFound);

#endif
}

NAMESPACE_PROVIDEREND
