#include "RDP.h"
#include "CpuDetect.h"
#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_PROVIDER

const std::string RDP::CLASS_NAME("RDP");

//~~~Constructor~~~//

RDP::RDP(RdEngines RdEngine)
	:
	m_engineType(RdEngine)
{
	Reset();
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

void RDP::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	if (m_engineType == RdEngines::None)
	{
		throw CryptoRandomException("RDP:GetBytes", "Random provider is not available!");
	}
	if (m_engineType == RdEngines::RdSeed && Output.size() > SEED_MAX)
	{
		throw CryptoRandomException("RDP:GetBytes", "The seed providers maximum output is 64MB per request!");
	}

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
			const size_t RMDLEN = Utility::IntUtils::Min(sizeof(rnd), Length);
			Utility::MemUtils::CopyFromValue(rnd, Output, Offset, RMDLEN);
			Offset += RMDLEN;
			Length -= RMDLEN;
			failCtr = 0;
		}
		else
		{
			++failCtr;

			if ((m_engineType == RdEngines::RdRand && failCtr >= RDR_RETRY) || failCtr >= RDS_RETRY)
			{
				throw CryptoRandomException("RDP:GetBytes", "Exceeded the maximum number of retries!");
			}
		}
	}
}

void RDP::GetBytes(std::vector<byte> &Output)
{
	std::vector<byte> rnd(Output.size());
	GetBytes(rnd, 0, rnd.size());
	Utility::MemUtils::Copy(rnd, 0, Output, 0, rnd.size());
}

std::vector<byte> RDP::GetBytes(size_t Length)
{
	std::vector<byte> rnd(Length);
	GetBytes(rnd, 0, rnd.size());

	return rnd;
}

uint RDP::Next()
{
	std::vector<byte> rnd(sizeof(uint));
	GetBytes(rnd);
	uint val = 0;
	Utility::MemUtils::CopyToValue(rnd, 0, val, sizeof(uint));

	return val;
}

void RDP::Reset()
{
	Common::CpuDetect detect;

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
	}
}

NAMESPACE_PROVIDEREND
