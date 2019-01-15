#include "RDP.h"
#include "CpuDetect.h"
#include "Intrinsics.h"
#include "IntegerTools.h"

NAMESPACE_PROVIDER

using Utility::MemoryTools;

const std::string RDP::CLASS_NAME("RDP");

//~~~Constructor~~~//

RDP::RDP(RdEngines RdEngineType)
	:
	m_engineType(RdEngineType != RdEngines::None ? RdEngineType :
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("Random provider is not available!"), ErrorCodes::IllegalOperation))
{
#if !defined(__AVX__) && !defined(__AVX2__) && !defined(__AVX512__)
	throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("DRAND is not supported on this system!"), ErrorCodes::IllegalOperation);
#endif

	CpuDetect detect;

	if (detect.RDSEED())
	{
		m_engineType = RdEngines::RdSeed;
	}
	else if (detect.RDRAND())
	{
		m_engineType = RdEngines::RdRand;
	}
	else
	{
		m_engineType = RdEngines::None;
		throw CryptoRandomException(CLASS_NAME, std::string("Constructor"), std::string("DRAND is not supported on this system!"), ErrorCodes::NotFound);
	}
}

RDP::~RDP()
{
	m_engineType = RdEngines::None;
}

//~~~Accessors~~~//

const Enumeration::Providers RDP::Enumeral()
{
	return Enumeration::Providers::RDP;
}

const bool RDP::IsAvailable()
{
	return m_engineType != RdEngines::None;
}

const std::string RDP::Name()
{
	return CLASS_NAME;
}

//~~~Public Functions~~~//

void RDP::Generate(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (m_engineType == RdEngines::RdSeed && Output.size() > SEED_MAX)
	{
		throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::IllegalOperation);
	}

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)

	int res = 0;
	size_t failCtr = 0;

	while (Length != 0)
	{
#if defined(CEX_IS_X64)
		ulong rnd = 0;
		if (m_engineType == RdEngines::RdSeed)
		{
			res = _rdseed64_step(&rnd);
		}
		else
		{
			res = _rdrand64_step(&rnd);
		}
#else
		uint rnd = 0;
		if (m_engineType == RdEngines::RdSeed)
		{
			res = _rdseed32_step(&rnd);
		}
		else
		{
			res = _rdrand32_step(&rnd);
		}
#endif

		if (res == RDR_SUCCESS)
		{
			const size_t RMDLEN = Utility::IntegerTools::Min(sizeof(rnd), Length);
			MemoryTools::CopyFromValue(rnd, Output, Offset, RMDLEN);
			Offset += RMDLEN;
			Length -= RMDLEN;
			failCtr = 0;
		}
		else
		{
			++failCtr;

			if ((m_engineType == RdEngines::RdRand && failCtr >= RDR_RETRY) || failCtr >= RDS_RETRY)
			{
				throw CryptoRandomException(CLASS_NAME, std::string("Generate"), std::string("The seed providers maximum output is 64MB per request!"), ErrorCodes::MaxExceeded);
			}
		}
	}
#endif
}

void RDP::Generate(std::vector<byte> &Output)
{
	std::vector<byte> rnd(Output.size());
	Generate(rnd, 0, rnd.size());
	MemoryTools::Copy(rnd, 0, Output, 0, rnd.size());
}

std::vector<byte> RDP::Generate(size_t Length)
{
	std::vector<byte> rnd(Length);
	Generate(rnd, 0, rnd.size());

	return rnd;
}

ushort RDP::NextUInt16()
{
	ushort x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ushort)), 0, x, sizeof(ushort));

	return x;
}

uint RDP::NextUInt32()
{
	uint x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(uint)), 0, x, sizeof(uint));

	return x;
}

ulong RDP::NextUInt64()
{
	ulong x = 0;
	MemoryTools::CopyToValue(Generate(sizeof(ulong)), 0, x, sizeof(ulong));

	return x;
}

void RDP::Reset()
{
}

NAMESPACE_PROVIDEREND
