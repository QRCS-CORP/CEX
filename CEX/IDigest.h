#ifndef _CEX_IDIGEST_H
#define _CEX_IDIGEST_H

#include "CexDomain.h"
#include "CryptoDigestException.h"
#include "Digests.h"
#include "ISymmetricKey.h"
#include "ParallelOptions.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;
using Enumeration::Digests;
using Key::Symmetric::ISymmetricKey;
using Common::ParallelOptions;

/// <summary>
/// Hash Digest Interface
/// </summary>
class IDigest
{
public:

	IDigest(const IDigest&) = delete;
	IDigest& operator=(const IDigest&) = delete;

	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	IDigest() {}

	/// <summary>
	/// Finalizer
	/// </summary>
	virtual ~IDigest() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Digests internal block size in bytes
	/// </summary>
	virtual size_t BlockSize() = 0;

	/// <summary>
	/// Get: Size of returned hash value in bytes
	/// </summary>
	virtual size_t DigestSize() = 0;

	/// <summary>
	/// Get: The digests type name
	/// </summary>
	virtual Digests Enumeral() = 0;

	/// <summary>
	/// Get: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() = 0;

	/// <summary>
	/// Get: The digests class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Get: Parallel block size; the byte-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.<para>
	/// </summary>
	virtual const size_t ParallelBlockSize() = 0;

	/// <summary>
	/// Get/Set: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Changes to these values must be made before the <see cref="Initialize(SymmetricKey)"/> function is called.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The hash output value array</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Do final processing and get the hash value
	/// </summary>
	/// 
	/// <param name="Output">The Hash output value array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <returns>Size of Hash value</returns>
	virtual size_t Finalize(std::vector<byte> &Output, const size_t OutOffset) = 0;

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	virtual void ParallelMaxDegree(size_t Degree) = 0;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Update the message digest with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input) = 0;

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	virtual void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) = 0;
};

NAMESPACE_DIGESTEND
#endif

