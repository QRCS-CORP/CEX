#ifndef CEX_TIMESTAMP_H
#define CEX_TIMESTAMP_H

#include "CexDomain.h"
#include "SystemTools.h"

NAMESPACE_TOOLS

/// <summary>
/// Internal class, wraps the highest available system time stamp
/// </summary>
class TimeStamp
{
private:

	bool m_hasTsc;
	uint64_t m_msCounter;
	uint64_t m_tmFrequency;

public:

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	TimeStamp();

	/// <summary>
	/// Returns the number of time units (frequency) elapsed
	/// </summary>
	/// 
	/// <returns>Return elapsed interval</returns>
	uint64_t Elapsed();

	/// <summary>
	/// The timing frequency in ticks
	/// </summary>
	uint64_t Frequency();

	/// <summary>
	/// Reset the counter value to 0
	/// </summary>
	void Reset();

	/// <summary>
	/// Store the reference time
	/// </summary>
	void Start();
};

NAMESPACE_TOOLSEND
#endif
