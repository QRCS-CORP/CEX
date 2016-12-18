#include "RDP.h"
#include "IntUtils.h"
#include "CpuDetect.h"
#if !defined(CEX_USE_GCC_INLINE_ASM)
#	include <immintrin.h>
#endif

NAMESPACE_PROVIDER

//** Public Methods **//

void RDP::Destroy()
{
	m_engineType = RdEngines::RdRand;
}

void RDP::GetBytes(std::vector<byte> &Output)
{
	if (m_engineType == RdEngines::RdSeed && Output.size() > RDSEEDMAX)
		throw CryptoRandomException("RDP:GetBytes", "The seed providers maximum output is 64MB per request!");

	size_t prcLen = Output.size();
	size_t prcOff = 0;

	do
	{
		int32_t rnd = Next();
		size_t prcRmd = Utility::IntUtils::Min(sizeof(int32_t), prcLen);
		memcpy(&Output[prcOff], &rnd, prcRmd);
		prcOff += prcRmd;
		prcLen -= prcRmd;
	} 
	while (prcLen != 0);
}

void RDP::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (Offset + Length > Output.size())
		throw CryptoRandomException("CSP:GetBytes", "The array is too small to fulfill this request!");

	std::vector<byte> rnd(Length);
	GetBytes(rnd);
	memcpy(&Output[Offset], &rnd[0], rnd.size());
}

std::vector<byte> RDP::GetBytes(size_t Length)
{
	std::vector<byte> data(Length);
	GetBytes(data);

	return data;
}

uint32_t RDP::Next()
{
	if (!m_isAvailable)
		throw CryptoRandomException("RDP:Engine", "Random provider is not available!");

	const size_t RTRCNT = (m_engineType == RdEngines::RdRand) ? RDRRETRY : RDSRETRY;
	uint32_t rnd = 0;

	for (size_t i = 0; i != RTRCNT + 1; ++i)
	{
		if (i == RTRCNT)
			throw CryptoRandomException("RDP:GetBytes", "The provider retry count has been exceeded!");

		int res = 0;

		if (m_engineType == RdEngines::RdSeed)
		{
#if defined(CEX_USE_GCC_INLINE_ASM)
			asm(".byte 0x0F, 0xC7, 0xF8; adcl $0,%1" :
			"=a" (r), "=rnd" (res) : "0" (r), "1" (res) : "cc");
#else
			res = _rdseed32_step(&rnd);
#endif
		}
		else
		{
#if defined(CEX_USE_GCC_INLINE_ASM)
			asm(".byte 0x0F, 0xC7, 0xF0; adcl $0,%1" :
			"=a" (r), "=rnd" (res) : "0" (r), "1" (res) : "cc");
#else
			res = _rdrand32_step(&rnd);
#endif
		}

		if (res == RDSUCCESS)
			break;
	}

	return rnd;
}

void RDP::Reset()
{
	Common::CpuDetect detect;

	if (detect.RDRAND() || detect.RDSEED())
		m_isAvailable = true;

	if (m_isAvailable && !detect.RDSEED())
		m_engineType = RdEngines::RdRand;
}

NAMESPACE_PROVIDEREND