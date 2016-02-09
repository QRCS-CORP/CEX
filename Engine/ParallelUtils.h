#ifndef _CEXENGINE_PARALLELUTILS_H
#define _CEXENGINE_PARALLELUTILS_H

#include "Common.h"

#if defined(ANDROID) && defined(_OPENMP)
	#include <omp.h>
#elif defined(_WIN32)
	#include <Windows.h>
	#include <ppl.h>
#else
	#include <future>
#endif

NAMESPACE_UTILITY

/// <summary>
/// Parallel functions class
/// </summary> 
class ParallelUtils
{
public:

	template <class Lockable>
	/// <summary>
	/// Lock a thread instance.
	/// <para>ex. lock<std::mutex> lock(mtx);</para>
	/// </summary> 
	class lock 
	{
	private:
		Lockable &mtx;

	public:
		/// <summary>
		/// Lock a thread instance
		/// </summary> 
		/// 
		/// <param name="m">The thread</param>
		lock(Lockable & m) : mtx(m) 
		{
			mtx.lock();
		}
		~lock() 
		{
			mtx.unlock();
		}
	};

	/// <summary>
	/// Get The number of processors available on the system
	/// </summary>
	static int ProcessorCount();

	/// <summary>
	/// A multi platform Parallel For loop
	/// </summary>
	/// 
	/// <param name="From">The starting position</param> 
	/// <param name="To">The ending position</param>
	/// <param name="F">The function delegate</param>
	static void ParallelFor(int From, int To, const std::function<void(int)> &F);
};

NAMESPACE_UTILITYEND
#endif
