#ifndef CEX_IDIGEST_H
#define CEX_IDIGEST_H

#include "CexDomain.h"
#include "CryptoDigestException.h"
#include "Digests.h"
#include "ParallelOptions.h"

NAMESPACE_DIGEST

using Exception::CryptoDigestException;
using Enumeration::Digests;
using Enumeration::ErrorCodes;

/// <summary>
/// The message digest virtualnterface class.
/// <para>This class can be used to create functions that will accept any of the implemented message digest instances as a parameter.</para>
/// </summary>
class IDigest
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IDigest(const IDigest&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IDigest& operator=(const IDigest&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IDigest() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IDigest() noexcept 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The message-digests internal block size in bytes
	/// </summary>
	virtual size_t BlockSize() = 0;

	/// <summary>
	/// Read Only: The message-digests output hash-size in bytes
	/// </summary>
	virtual size_t DigestSize() = 0;

	/// <summary>
	/// Read Only: The message-digests enumeration type-name
	/// </summary>
	virtual const Digests Enumeral() = 0;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() = 0;

	/// <summary>
	/// Read Only: The message-digests formal class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	virtual const size_t ParallelBlockSize() = 0;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Changes to these values must be made before the <see cref="Initialize(SymmetricKey)"/> function is called.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Compute the hash value in a single-step using the input message and the output vector receiving the hash code.
	/// <para>Not recommended for vector sizes exceeding 1MB, use the Update/Finalize api to loop in large data.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message byte-vector</param>
	/// <param name="Output">The output vector receiving the final hash code; must be at least DigestSize in length</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Finalize message processing and return the hash code.
	/// <para>Used in conjunction with the Update api to process a message, and then return the finalized hash code.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output vector receiving the final hash code; must be at least DigestSize in length</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	virtual void Finalize(std::vector<byte> &Output, size_t OutOffset) = 0;

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if the degree parameter is invalid</exception>
	virtual void ParallelMaxDegree(size_t Degree) = 0;

	/// <summary>
	/// Reset the message-digests internal state
	/// </summary>
	virtual void Reset() = 0;

	/// <summary>
	/// Update the message digest with a single unsigned 8-bit integer
	/// </summary>
	/// 
	/// <param name="Input">The 8-bit integer added to process</param>
	virtual void Update(byte Input) = 0;

	/// <summary>
	/// Update the message digest with a single unsigned 32-bit integer
	/// </summary>
	/// 
	/// <param name="Input">The 32-bit integer to process</param>
	virtual void Update(uint Input) = 0;

	/// <summary>
	/// Update the message digest with a single unsigned 64-bit integer
	/// </summary>
	/// 
	/// <param name="Input">The 64-bit integer to process</param>
	virtual void Update(ulong Input) = 0;

	/// <summary>
	/// Update the message digest with a vector using offset and length parameters.
	/// <para>Used in conjunction with the Finalize function, processes message data used to generate the hash code.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input message byte-vector</param>
	/// <param name="InOffset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	virtual void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length) = 0;
};

NAMESPACE_DIGESTEND
#endif

