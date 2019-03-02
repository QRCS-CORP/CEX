#ifndef CEX_PARALLELOPTIONS_H
#define CEX_PARALLELOPTIONS_H

#include "CexDomain.h"
#include "CpuCores.h"
#include "CryptoProcessingException.h"
#include "SimdProfiles.h"

NAMESPACE_ROOT

using Enumeration::CpuCores;
using Exception::CryptoProcessingException;
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
private:

	static const std::string CLASS_NAME;

	struct AutoParallelParams
	{
		AutoParallelParams()
			:
			IsParallel(false),
			MaxDegree(0),
			ParallelBlockSize(0)
		{
		}

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
	bool m_hasPrefetch;
	bool m_hasSHA2;
	bool m_hasSimd128;
	bool m_hasSimd256;
	bool m_hasSimd512;
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
	size_t m_virtualCores;
	bool m_wideBlock;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	ParallelOptions(const ParallelOptions&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	ParallelOptions& operator=(const ParallelOptions&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	ParallelOptions() = delete;

	/// <summary>
	/// Constructor: instantiate this class using automated calculation of recommended values based on the hardware profile.
	/// <para>Initializes and calculates the default recommended values. 
	/// Sizes are auto-calculated based on processor cache sizes, cpu core count, and SIMD availability, to favour a high-performance profile.</para>
	/// </summary>
	/// 
	/// <param name="BlockSize">The calling algorithms base input block-size in bytes</param>
	/// <param name="SimdMultiply">The calling algorithm supports SIMD pipelining; engages a multiplier used to calculate the optimum parallel block size.</param>
	/// <param name="ReservedCache">The amount of L1 cache in bytes to reserve for arrays and working variables used by the calling algorithm.
	/// <para>Setting this value to the sum size (or greater) of the classes state variables, can reduce the frequency of L1 cache eviction of that state, 
	/// which in turn provides faster run-times and resiliance against some forms of timing attacks.</para></param>
	/// <param name="SplitChannel">The calling algorithm uses two channels of equal size Input and Output when processing data</param>
	/// <param name="ParallelMaxDegree">The maximum number of processor cores used by the algorithm during parallel processing; if set to zero, uses total number of processor cores</param>
	ParallelOptions(size_t BlockSize, bool SimdMultiply, size_t ReservedCache, bool SplitChannel, size_t ParallelMaxDegree = 0);

	/// <summary>
	/// Constructor: instantiate this class, setting each value manually.
	/// </summary>
	/// 
	/// <param name="BlockSize">The input block-size in bytes of the target algorithm</param>
	/// <param name="Parallel">Multi threaded execution of the algorithm is enabled</param>
	/// <param name="ParallelBlockSize">The input block-size required to trigger parallel processing</param>
	/// <param name="ParallelMaxDegree">The maximum number of processor cores used by the algorithm during parallel processing</param>
	/// <param name="SimdMultiply">The target algorithm uses SIMD instructions multiplier to calculate parallel block sizes</param>
	/// <param name="ReservedCache">The amount of L1 cache in bytes to reserve for arrays and working variables used by the calling algorithm.
	/// <para>Setting this value to the sum size (or greater) of the classes state variables, can reduce the frequency of L1 cache eviction of that state, 
	/// which in turn provides faster run-times and resiliance against some forms of timing attacks.</para></param>
	/// <param name="SplitChannel">The calling algorithm uses two channels of equal size Input and Output when processing data</param>
	ParallelOptions(size_t BlockSize, bool Parallel, size_t ParallelBlockSize, size_t ParallelMaxDegree, bool SimdMultiply, size_t ReservedCache, bool SplitChannel);

	/// <summary>
	/// Finalize this class and clear resources
	/// </summary>
	~ParallelOptions();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The settings are the default auto-generated recommended values
	/// </summary>
	const bool IsDefault();

	/// <summary>
	/// Read Only: Block size of the algorithm in bytes
	/// </summary>
	const size_t BlockSize();

	/// <summary>
	/// Read Only: Returns True if the system supports prefetch intrinsics
	/// </summary>
	const bool HasPrefetch();

	/// <summary>
	/// Read Only: Returns True if the system supports SHA2 intrinsics
	/// </summary>
	const bool HasSHA2();

	/// <summary>
	/// Read Only: Returns True if the system supports 128bit SSE3 SIMD intrinsics
	/// </summary>
	const bool HasSimd128();

	/// <summary>
	/// Read Only: Returns True if the system supports 256bit AVX2 intrinsics
	/// </summary>
	const bool HasSimd256();

	/// <summary>
	/// Read Only: The total size in bytes of the L1 Data cache available on the system
	/// </summary>
	const size_t L1DataCacheTotalSize();

	/// <summary>
	/// Read Only: The amount of L1 cache in bytes to reserve for tables and working variables used by the calling algorithm.
	/// <para>Setting this value to the sum size (or greater) of the class state variables, 
	/// can reduce the frequency of L1 cache eviction for that state, 
	/// which in turn provides faster run-times and resiliance against some forms of timing attacks.</para>
	/// </summary>
	const size_t L1DataCacheReserved();

	/// <summary>
	/// Read/Write: Enable automatic processor parallelization
	/// </summary>
	bool &IsParallel();

	/// <summary>
	/// Read: The recommended parallel block size.
	/// </summary>
	const size_t ParallelBlockSize();

	/// <summary>
	/// Read Only: Maximum input block byte length when using multi-threaded processing
	/// </summary>
	const size_t ParallelMaximumSize();

	/// <summary>
	/// Read Only: The smallest valid ParallelBlockSize; parallel blocks must be a multiple of this size
	/// </summary>
	const size_t ParallelMinimumSize();

	/// <summary>
	/// Read Only: The maximum number of threads allocated when using multi-threaded processing.
	/// <para>Changes to this value must be made through the SetMaxDegree(size_t) function.</para>
	/// </summary>
	const size_t ParallelMaxDegree();

	/// <summary>
	/// Read Only: The number of processor cores available on the system
	/// </summary>
	const size_t PhysicalCores();

	/// <summary>
	/// Read Only: The maximum number of processor cores available on the system including virtul cores
	/// </summary>
	const size_t ProcessorCount();

	/// <summary>
	/// Read Only: The maximum supported SIMD instruction set
	/// </summary>
	const SimdProfiles SimdProfile();

	/// <summary>
	/// Read Only: The number of virtual (hyper-threading) processor cores available on the system
	/// </summary>
	const size_t VirtualCores();

	/// <summary>
	/// Read/Write: Enable wide block initialization parameters (in development)
	/// </summary>
	bool &WideBlock();

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
	/// Reset all internal data to defaults
	/// </summary>
	void Reset();

	/// <summary>
	/// Define parallel-block length in bytes.
	/// <para>Re-calculates the auto-configured [recommended] valuesand replaces it with a user-defined size.</para>
	/// </summary>
	/// 
	/// <param name="BlockSize">The new parallel block-size</param>
	void SetBlockSize(size_t BlockSize);

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


NAMESPACE_ROOTEND
#endif
