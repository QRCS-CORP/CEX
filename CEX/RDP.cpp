#include "RDP.h"
#include "CpuDetect.h"
#include "Intrinsics.h"
#include "IntUtils.h"

NAMESPACE_PROVIDER

const std::string RDP::CLASS_NAME("RDP");

//~~~Constructor~~~//

RDP::RDP(RdEngines RdEngine)
	:
	m_engineType(RdEngine),
	m_isAvailable(false)
{
	Reset();
}

RDP::~RDP()
{
	m_engineType = RdEngines::RdRand;
	m_isAvailable = false;
}

//~~~Accessors~~~//

const Enumeration::Providers RDP::Enumeral() 
{ 
	return Enumeration::Providers::RDP; 
}

const bool RDP::IsAvailable() 
{
	return m_isAvailable; 
}

const std::string RDP::Name() 
{ 
	return CLASS_NAME; 
}

//~~~Public Functions~~~//

void RDP::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CexAssert(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	if (m_engineType == RdEngines::RdSeed && Output.size() > RDSEEDMAX)
	{
		throw CryptoRandomException("RDP:GetBytes", "The seed providers maximum output is 64MB per request!");
	}

	if (!m_isAvailable)
	{
		throw CryptoRandomException("RDP:GetBytes", "Random provider is not available!");
	}

	size_t len = Length;
	size_t off = Offset;
	size_t rmd;

	do
	{
		uint rnd32 = Next();
		rmd = Utility::IntUtils::Min(sizeof(uint), len);
		Utility::MemUtils::CopyFromValue(rnd32, Output, off, rmd);
		off += rmd;
		len -= rmd;
	} 
	while (len != 0);
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
	if (!m_isAvailable)
	{
		throw CryptoRandomException("RDP:Next", "Random provider is not available!");
	}

	const size_t MAXITR = (m_engineType == RdEngines::RdRand) ? RDRRETRY : RDSRETRY;
	uint rnd = 0;

	for (size_t i = 0; i < MAXITR + 1; ++i)
	{
		int result = 0;

		if (m_engineType == RdEngines::RdSeed)
		{
			result = _rdseed32_step(&rnd);
		}
		else
		{
			result = _rdrand32_step(&rnd);
		}

		if (result == RDSUCCESS)
		{
			break;
		}

		if (i == MAXITR)
		{
			throw CryptoRandomException("RDP:Next", "The provider retry count has been exceeded!");
		}
	}

	return rnd;
}

void RDP::Reset()
{
	Common::CpuDetect detect;

	if (detect.RDRAND() || detect.RDSEED())
	{
		m_isAvailable = true;
	}

	if (m_isAvailable && !detect.RDSEED())
	{
		m_engineType = RdEngines::RdRand;
	}
}

NAMESPACE_PROVIDEREND