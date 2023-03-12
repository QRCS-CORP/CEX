#include "TimeStamp.h"

NAMESPACE_TOOLS

using Tools::SystemTools;

TimeStamp::TimeStamp()
	:
	m_hasTsc(SystemTools::HasRdtsc()),
	m_msCounter(0),
	m_tmFrequency(m_hasTsc ? SystemTools::GetRdtscFrequency() : 100)
{
}

uint64_t TimeStamp::Elapsed()
{
	return SystemTools::TimeStamp(m_hasTsc) - m_msCounter;
}

uint64_t TimeStamp::Frequency()
{
	return m_tmFrequency;
}

void TimeStamp::Reset()
{
	m_msCounter = 0;
}

void TimeStamp::Start()
{
	m_msCounter = SystemTools::TimeStamp(m_hasTsc);
}

NAMESPACE_TOOLSEND
