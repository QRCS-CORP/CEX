#ifndef _CEX_PARALLELOPTIONS_H
#define _CEX_PARALLELOPTIONS_H

#include "CexDomain.h"
#include "SimdProfiles.h"

NAMESPACE_COMMON

using Enumeration::SimdProfiles;

/// <summary>
/// The ParallelOptions class.
/// <para>Contains system available intrinsics options, and parallel processing information.</para>
/// </summary>
/// 
/// <example>
/// <description>Populating a ParallelOptions structure:</description>
/// <code>
///    ParallelOptions prl(
///        16,          // a base block size of 16 bytes
///        false,		// parallel not using simd block multiplier
///		   1024,		// subtract pre-cached elements
///		   true);		// dual channel algorithm (in/out)
/// </code>
/// </example>
class ParallelOptions
{
public:

private:

	struct AutoParallelParams
	{
		bool IsParallel;
		size_t MaxDegree;
		size_t ParallelBlockSize;
	};

	// 16kb min
	const size_t DEF_DATACACHE = 16384;
	// 32mb, not enforced
	const size_t MAX_PRLALLOC = DEF_DATACACHE * 2000;

	bool m_autoInit;
	size_t m_blockSize;
	AutoParallelParams m_defaultParams;
	bool m_hasSHA2;
	bool m_hasSimd128;
	bool m_hasSimd256;
	bool m_isParallel;
	size_t m_l1DataCacheReserved;
	size_t m_l1DataCacheTotal;
	bool m_overrideMaxDegree;
	size_t m_parallelBlockSize;
	size_t m_parallelMaxDegree;
	size_t m_parallelMinimumSize;
	size_t m_physicalCores;
	size_t m_processorCount;
	SimdProfiles m_simdDetected;
	bool m_simdMultiply;
	bool m_splitChannel;
	bool m_wideBlock;
	size_t m_virtualCores;

public:

	//~~~Properties~~~//

	/// <summary>
	/// Get: The settings are the default auto-generated recommended values
	/// </summary>
	const bool IsDefault()
	{
		return (m_defaultParams.IsParallel == m_isParallel &&
			m_defaultParams.MaxDegree == m_parallelMaxDegree &&
			m_defaultParams.ParallelBlockSize == m_parallelBlockSize);
	}

	/// <summary>
	/// Get: Block size of the algorithm in bytes
	/// </summary>
	const size_t BlockSize() { return m_blockSize; }

	/// <summary>
	/// Get: Returns True if the system supports SHA2 intrinsics
	/// </summary>
	const bool HasSHA2() { return m_hasSHA2; }

	/// <summary>
	/// Get: Returns True if the system supports 128bit SSE3 SIMD intrinsics
	/// </summary>
	const bool HasSimd128() { return m_hasSimd128; }

	/// <summary>
	/// Get: Returns True if the system supports 256bit AVX2 intrinsics
	/// </summary>
	const bool HasSimd256() { return m_hasSimd256; }

	/// <summary>
	/// Get: The total size in bytes of the L1 Data cache available on the system
	/// </summary>
	const size_t L1DataCacheTotalSize() { return m_l1DataCacheTotal; }

	/// <summary>
	/// Get: The amount of L1 cache in bytes to reserve for tables and working variables used by the calling algorithm.
	/// <para>Setting this value to the sum size (or greater) of the class state variables, 
	/// can reduce the frequency of L1 cache eviction for that state, 
	/// which in turn provides faster run-times and resiliance against some forms of timing attacks.<para>
	/// </summary>
	const size_t L1DataCacheReserved() { return m_l1DataCacheReserved; }

	/// <summary>
	/// Get/Set: Enable automatic processor parallelization
	/// </summary>
	bool &IsParallel() { return m_isParallel; }

	/// <summary>
	/// Get/Set: Parallel block size; must be a multiple of <see cref="ParallelMinimumSize"/>.</para>
	/// </summary>
	size_t &ParallelBlockSize() { return m_parallelBlockSize; }

	/// <summary>
	/// Get: Maximum input block byte length when using multi-threaded processing
	/// </summary>
	const size_t ParallelMaximumSize() { return MAX_PRLALLOC; }

	/// <summary>
	/// Get: The smallest valid ParallelBlockSize; parallel blocks must be a multiple of this size
	/// </summary>
	const size_t ParallelMinimumSize() { return m_parallelMinimumSize; }

	/// <summary>
	/// Get: The maximum number of threads allocated when using multi-threaded processing.
	/// <para>Changes to this value must be made through the SetMaxDegree(size_t) function.</para>
	/// </summary>
	const size_t ParallelMaxDegree() { return m_parallelMaxDegree; }

	/// <summary>
	/// Get: The number of processor cores available on the system
	/// </summary>
	const size_t PhysicalCores() { return m_physicalCores; }

	/// <summary>
	/// Get: The maximum number of processor cores available on the system
	/// </summary>
	const size_t ProcessorCount() { return m_virtualCores != 0 ? m_virtualCores : m_physicalCores; }

	/// <summary>
	/// Get: The maximum supported SIMD instruction set
	/// </summary>
	const SimdProfiles SimdProfile() { return m_simdDetected; }

	/// <summary>
	/// Get: The number of virtual (hyper-threading) processor cores available on the system
	/// </summary>
	const size_t VirtualCores() { return m_virtualCores; }

	/// <summary>
	/// Get/Set: Enable wide block initialization parameters (in development)
	/// </summary>
	bool &WideBlock() { return m_wideBlock; }

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class using automated calculation of recommended values based on the hardware profile.
	/// <para>Initializes and calculates the default recommended values. 
	/// Sizes are auto-calculated based on processor cache sizes, cpu core count, and SIMD availability, to favour a high-performance profile.</para>
	/// </summary>
	/// 
	/// <param name="BlockSize">The calling algorithms base input block-size in bytes</param>
	/// <param name="SimdMultiply">The calling algorithm supports SIMD pipelining; engages a multiplier used to calculate the optimum parallel block size.</param>
	/// <param name="ReservedCache">The amount of L1 cache in bytes to reserve for arrays and working variables used by the calling algorithm.
	/// <para>Setting this value to the sum size (or greater) of the classes state variables, can reduce the frequency of L1 cache eviction of that state, 
	/// which in turn provides faster run-times and resiliance against some forms of timing attacks.<para></param>
	/// <param name="SplitChannel">The calling algorithm uses two channels of equal size Input and Output when processing data</param>
	/// <param name="ParallelMaxDegree">The maximum number of processor cores used by the algorithm during parallel processing; if set to zero, uses total number of processor cores</param>
	explicit ParallelOptions(size_t BlockSize, bool SimdMultiply, size_t ReservedCache, bool SplitChannel, size_t ParallelMaxDegree = 0);

	/// <summary>
	/// Instantiate this class, setting each value manually.
	/// </summary>
	/// 
	/// <param name="BlockSize">The input block-size in bytes of the target algorithm</param>
	/// <param name="Parallel">Multi threaded execution of the algorithm is enabled</param>
	/// <param name="ParallelBlockSize">The input block-size required to trigger parallel processing</param>
	/// <param name="ParallelMaxDegree">The maximum number of processor cores used by the algorithm during parallel processing</param>
	/// <param name="SimdMultiply">The target algorithm uses SIMD instructions multiplier to calculate parallel block sizes</param>
	/// <param name="ReservedCache">The amount of L1 cache in bytes to reserve for arrays and working variables used by the calling algorithm.
	/// <para>Setting this value to the sum size (or greater) of the classes state variables, can reduce the frequency of L1 cache eviction of that state, 
	/// which in turn provides faster run-times and resiliance against some forms of timing attacks.<para></param>
	/// <param name="SplitChannel">The calling algorithm uses two channels of equal size Input and Output when processing data</param>
	explicit ParallelOptions(size_t BlockSize, bool Parallel, size_t ParallelBlockSize, size_t ParallelMaxDegree, bool SimdMultiply, size_t ReservedCache, bool SplitChannel);

	/// <summary>
	/// Finalize this class and clear resources
	/// </summary>
	~ParallelOptions();

	//~~~Public Functions~~~//

	/// <summary>
	/// Calculate the parallel-block and parallel-minimum sizes based on the max number of cores assigned, or changes to .
	/// <para>This function is first run when the ParallelOptions class is instantiated, generating the recommended default values based on system capabilities.
	/// Running this function re-calculates the sizes based on user initiated changes to ParallelBlockSize, ParallelMaxDegree, or IsParallel properties.</para>
	/// </summary>
	void Calculate();

	/// <summary>
	/// Define parallel-block and parallel-minimum sizes based on the max number of cores assigned.
	/// <para>Re-calculates the default recommended option values based on the number of processor cores (threads) assigned to the operation.
	/// The MaxDegree value is the maximum number of processor cores used by the containing algorithm during parallel operations.
	/// This value must be an even non-zero number, and less than or equal to the total nuumber of processor virtual cores, i.e. 2, 4, 8.</para>
	/// </summary>
	///
	/// <param name="Parallel">Enable or disable multi-threading for this algorithm</param>
	/// <param name="ParallelBlockSize">A user defined parallel block-size; the natural input size that triggers parallel processing</param>
	/// <param name="MaxDegree">The maximum number of threads to use with multi-threaded operations. 
	/// <para>This must be an even positive number no greater than the number of processor cores.</para></param>
	void Calculate(bool Parallel, size_t ParallelBlockSize, size_t MaxDegree);

	/// <summary>
	/// Reset the internal state
	/// </summary>
	void Reset();

	/// <summary>
	/// Define parallel-block and parallel-minimum sizes based on the max number of cores assigned.
	/// <para>Re-calculates the default recommended option values based on the number of processor cores (threads) assigned to the operation.
	/// The MaxDegree value is the maximum number of processor cores used by the containing algorithm during parallel operations.
	/// This value must be an even non-zero number, and less than or equal to the total nuumber of processor virtual cores, i.e. 2, 4, 8.</para>
	/// </summary>
	/// 
	/// <param name="MaxDegree">The maximum number of processor cores available to this algorithm; 
	/// a value of 0, or greater than the processors virtual-core count, defaults to the processors virtual-core count</param>
	void SetMaxDegree(size_t MaxDegree);

	//~~~Private Functions~~~//

	void Detect();
	void StoreDefaults();
};


NAMESPACE_COMMONEND
#endif