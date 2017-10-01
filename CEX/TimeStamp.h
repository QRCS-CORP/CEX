#ifndef CEX_TIMESTAMP_H
#define CEX_TIMESTAMP_H

#include "CexDomain.h"
#include "SysUtils.h"

NAMESPACE_UTILITY

/// <summary>
/// Wraps the highest available system time stamp
/// </summary>
class TimeStamp
{
private:

	bool m_hasTsc;
	ulong m_msCounter;
	ulong m_tmFrequency;

public:

	TimeStamp()
		:
		m_hasTsc(Utility::SysUtils::HasRdtsc()),
		m_msCounter(0),
		m_tmFrequency(m_hasTsc ? Utility::SysUtils::GetRdtscFrequency() : 100)
	{
	}

	/// <summary>
	/// Returns the number of time units (frequency) elapsed
	/// </summary>
	/// 
	/// <returns>Return elapsed interval</returns>
	ulong Elapsed()
	{
		return Utility::SysUtils::TimeStamp(m_hasTsc) - m_msCounter;
	}

	/// <summary>
	/// The timing frequency in ticks
	/// </summary>
	ulong Frequency()
	{
		return m_tmFrequency;
	}

	/// <summary>
	/// Reset the counter value to 0
	/// </summary>
	void Reset()
	{
		m_msCounter = 0;
	}

	/// <summary>
	/// Store the reference time
	/// </summary>
	void Start()
	{
		m_msCounter = Utility::SysUtils::TimeStamp(m_hasTsc);
	}
};

NAMESPACE_UTILITYEND
#endif