#include "TimeStamp.h"

NAMESPACE_UTILITY

TimeStamp::TimeStamp()
	:
	m_hasTsc(Utility::SystemTools::HasRdtsc()),
	m_msCounter(0),
	m_tmFrequency(m_hasTsc ? Utility::SystemTools::GetRdtscFrequency() : 100)
{
}

ulong TimeStamp::Elapsed()
{
	return Utility::SystemTools::TimeStamp(m_hasTsc) - m_msCounter;
}

ulong TimeStamp::Frequency()
{
	return m_tmFrequency;
}

void TimeStamp::Reset()
{
	m_msCounter = 0;
}

void TimeStamp::Start()
{
	m_msCounter = Utility::SystemTools::TimeStamp(m_hasTsc);
}

NAMESPACE_UTILITYEND
