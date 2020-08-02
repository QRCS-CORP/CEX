#include "Timer.h"
#include "CryptoProcessingException.h"
#include "IntegerTools.h"
#include <assert.h>
#include <stddef.h>
#include <time.h>

#if defined(CEX_OS_WINDOWS)
#	include <windows.h>
#elif defined(CEX_OS_UNIX)
#	include <sys/time.h>
#	include <sys/times.h>
#	include <unistd.h>
#endif

NAMESPACE_TOOLS

using Exception::CryptoProcessingException;
using Tools::IntegerTools;

double TimerBase::ConvertTo(TimerWord t, Unit unit)
{
	static ulong unitsPerSecondTable[] = { 1, 1000, 1000 * 1000, 1000 * 1000 * 1000 };

	assert(static_cast<size_t>(unit) < sizeof(unitsPerSecondTable) / sizeof(unitsPerSecondTable[0]));

	return static_cast<double>(static_cast<long>(t) * unitsPerSecondTable[static_cast<size_t>(unit)] / static_cast<long>(TicksPerSecond()));
}

void TimerBase::StartTimer()
{
	m_last = GetCurrentTimerValue();
	m_start = m_last;
	m_started = true;
}

double TimerBase::ElapsedTimeAsDouble()
{
	double ret;

	ret = 0.0;

	if (!m_stuckAtZero)
	{
		if (m_started)
		{
			TimerWord now = GetCurrentTimerValue();

			// protect against OS bugs where time goes backwards
			if (m_last < now)
			{
				m_last = now;
			}

			ret = ConvertTo(m_last - m_start, m_timerUnit);
		}
		else
		{
			StartTimer();
		}
	}

	return ret;
}

ulong TimerBase::ElapsedTime()
{
	double elapsed;

	elapsed = ElapsedTimeAsDouble();

	assert(elapsed <= ULONG_MAX);

	return static_cast<ulong>(elapsed);
}

TimerWord Timer::GetCurrentTimerValue()
{
#if defined(CEX_OS_WINDOWS)
	LARGE_INTEGER now;

	if (!QueryPerformanceCounter(&now))
	{
		throw CryptoProcessingException(std::string("ElapsedTime"), std::string("Timer"), std::string("QueryPerformanceCounter failed!"), Enumeration::ErrorCodes::Unreachable);
	}

	return static_cast<TimerWord>(now.QuadPart);

#elif defined(CEX_OS_UNIX)
	timeval now;
	gettimeofday(&now, NULL);

	return (static_cast<TimerWord>(now.tv_sec) * 1000000) + now.tv_usec;

#else
	return static_cast<TimerWord>(clock());
#endif
}

TimerWord Timer::TicksPerSecond()
{
#if defined(CEX_OS_WINDOWS)
	static LARGE_INTEGER freq = { 0 };

	if (freq.QuadPart == 0)
	{
		if (!QueryPerformanceFrequency(&freq))
		{
			throw CryptoProcessingException(std::string("TicksPerSecond"), std::string("Timer"), std::string("QueryPerformanceCounter failed!"), Enumeration::ErrorCodes::Unreachable);
		}
	}

	return freq.QuadPart;

#elif defined(CEX_OS_UNIX)
	return 1000000;
#else
	return CLOCKS_PER_SEC;
#endif
}

TimerWord ThreadUserTimer::GetCurrentTimerValue()
{
#if defined(CEX_OS_WINDOWS)

	TimerWord twrd;
	ulong high;
	static bool cthd;

	cthd = true;
	twrd = 0;

	if (cthd)
	{
		FILETIME now, ignored;

		if (!GetThreadTimes(GetCurrentThread(), &ignored, &ignored, &ignored, &now))
		{
			DWORD lastError = GetLastError();

			if (lastError == ERROR_CALL_NOT_IMPLEMENTED)
			{
				cthd = false;
				twrd = static_cast<TimerWord>(clock()) * (10 * 1000 * 1000 / CLOCKS_PER_SEC);
			}
			else
			{
				throw CryptoProcessingException(std::string("GetCurrentTimerValue"), std::string("Timer"), std::string("GetThreadTimes failed!"), Enumeration::ErrorCodes::Unreachable);
			}
		}
		else
		{
			high = static_cast<ulong>(now.dwHighDateTime);
			high <<= 32;

			twrd = static_cast<TimerWord>(high) + now.dwLowDateTime;
		}

	}

	return twrd;

#elif defined(CEX_OS_UNIX)
	tms now;
	times(&now);

	return now.tms_utime;
#else
	return clock();
#endif
}

TimerWord ThreadUserTimer::TicksPerSecond()
{
#if defined(CEX_OS_WINDOWS)
	return 10 * 1000 * 1000;
#elif defined(CEX_OS_UNIX)
	static const long ticksPerSecond = sysconf(_SC_CLK_TCK);

	return ticksPerSecond;
#else
	return CLOCKS_PER_SEC;
#endif
}

NAMESPACE_TOOLSEND