#ifndef CEX_TIMESTAMP_H
#define CEX_TIMESTAMP_H

#include "CexDomain.h"
#include "SystemTools.h"

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

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	TimeStamp();

	/// <summary>
	/// Returns the number of time units (frequency) elapsed
	/// </summary>
	/// 
	/// <returns>Return elapsed interval</returns>
	ulong Elapsed();

	/// <summary>
	/// The timing frequency in ticks
	/// </summary>
	ulong Frequency();

	/// <summary>
	/// Reset the counter value to 0
	/// </summary>
	void Reset();

	/// <summary>
	/// Store the reference time
	/// </summary>
	void Start();
};

NAMESPACE_UTILITYEND
#endif
