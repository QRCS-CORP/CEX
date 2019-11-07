#include "Timer.h"
#include "CryptoProcessingException.h"
#include "IntegerTools.h"
#include <assert.h>
#include <stddef.h>
#include <time.h>

#if defined(CEX_OS_WINDOWS)
#include <windows.h>
#elif defined(CEX_OS_UNIX)
#include <sys/time.h>
#include <sys/times.h>
#include <unistd.h>
#endif

NAMESPACE_UTILITY

using Exception::CryptoProcessingException;
using Utility::IntegerTools;

double TimerBase::ConvertTo(TimerWord t, Unit unit)
{
	static unsigned long unitsPerSecondTable[] = { 1, 1000, 1000 * 1000, 1000 * 1000 * 1000 };

	assert(unit < sizeof(unitsPerSecondTable) / sizeof(unitsPerSecondTable[0]));
	return (double)(long)t * unitsPerSecondTable[unit] / (long)TicksPerSecond();
}

void TimerBase::StartTimer()
{
	m_last = m_start = GetCurrentTimerValue();
	m_started = true;
}

double TimerBase::ElapsedTimeAsDouble()
{
	if (m_stuckAtZero)
		return 0;

	if (m_started)
	{
		TimerWord now = GetCurrentTimerValue();

		// protect against OS bugs where time goes backwards
		if (m_last < now)
		{
			m_last = now;
		}

		return ConvertTo(m_last - m_start, m_timerUnit);
	}

	StartTimer();
	return 0;
}

unsigned long TimerBase::ElapsedTime()
{
	double elapsed = ElapsedTimeAsDouble();

	assert(elapsed <= ULONG_MAX);

	return (unsigned long)elapsed;
}

TimerWord Timer::GetCurrentTimerValue()
{
#if defined(CEX_OS_WINDOWS)
	LARGE_INTEGER now;

	if (!QueryPerformanceCounter(&now))
	{
		throw CryptoProcessingException(std::string("ElapsedTime"), std::string("Timer"), std::string("QueryPerformanceCounter failed!"), Enumeration::ErrorCodes::Unreachable);
	}

	return now.QuadPart;

#elif defined(CEX_OS_UNIX)
	timeval now;
	gettimeofday(&now, NULL);

	return (TimerWord)now.tv_sec * 1000000 + now.tv_usec;

#else
	clock_t now;

	return clock();
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
	static bool getCurrentThreadImplemented = true;

	if (getCurrentThreadImplemented)
	{
		FILETIME now, ignored;
		if (!GetThreadTimes(GetCurrentThread(), &ignored, &ignored, &ignored, &now))
		{
			DWORD lastError = GetLastError();

			if (lastError == ERROR_CALL_NOT_IMPLEMENTED)
			{
				getCurrentThreadImplemented = false;
				goto GetCurrentThreadNotImplemented;
			}

			throw CryptoProcessingException(std::string("GetCurrentTimerValue"), std::string("Timer"), std::string("GetThreadTimes failed!"), Enumeration::ErrorCodes::Unreachable);
		}

		return now.dwLowDateTime + ((TimerWord)now.dwHighDateTime << 32);
	}
GetCurrentThreadNotImplemented:
	return (TimerWord)clock() * (10 * 1000 * 1000 / CLOCKS_PER_SEC);
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

NAMESPACE_UTILITYEND