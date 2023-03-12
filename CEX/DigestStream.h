// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// 
// Written by John G. Underhill, January 21, 2015
// Updated April 21, 2016
// Contact: develop@qscs.ca

#ifndef CEX_DIGESTSTREAM_H
#define CEX_DIGESTSTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "Event.h"
#include "IByteStream.h"
#include "IDigest.h"

NAMESPACE_PROCESSING

using Exception::CryptoProcessingException;
using Enumeration::Digests;
using Routing::Event;
using IO::IByteStream;
using Digest::IDigest;

/// <summary>
/// Digest stream helper class.
/// <para>Wraps a message digest stream function in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of hashing a stream:</description>
/// <code>
/// // create the instance
/// StreamDigest sdgt(Digests::SHA2256);
/// // get the hash code
/// hash = sdgt.Compute(Input);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Uses any of the implemented Digests using either the IDigest interface, or a Digests enumeration type.</description></item>
/// <item><description>This implementation has a Progress counter that returns total sum of bytes processed per either of the Compute() calls.</description></item>
/// </list>
/// </remarks>
class DigestStream
{
private:

	static const std::string CLASS_NAME;

	class DigestStreamState;
	std::unique_ptr<DigestStreamState> m_streamState;
	std::unique_ptr<IDigest> m_digestEngine;

public:

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	Event<int32_t> ProgressPercent;

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	DigestStream(const DigestStream&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	DigestStream& operator=(const DigestStream&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	DigestStream() = delete;

	/// <summary>
	/// Initialize the class with a digest enumeration type name
	/// </summary>
	/// 
	/// <param name="DigestType">The digest enumeration type</param>
	/// <param name="Parallel">Instantiates the multi-threaded implementation of the digest</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if invalid parameters are passed</exception>
	explicit DigestStream(Digests DigestType, bool Parallel = false);

	/// <summary>
	/// Initialize the class with a digest instance
	/// <para>Digest must be fully initialized before calling this method.</para>
	/// </summary>
	/// 
	/// <param name="Digest">The initialized Digest instance</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if a null digest is used</exception>
	explicit DigestStream(IDigest* Digest);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~DigestStream();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: Automatic processor parallelization capable.
	/// <para>This value is true if the host supports parallelization.
	/// If the system and digest configuration both support parallelization, it can be disabled by setting the IsParallel value in ParallelProfile to false.</para>
	/// </summary>
	bool IsParallel();

	/// <summary>
	/// Read Only: Parallel block size; the minimum input size that triggers parallel processing.
	/// </summary>
	size_t ParallelBlockSize();

	/// <summary>
	/// Read/Write: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.</para>
	/// </summary>
	ParallelOptions &ParallelProfile();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process the entire length of the source stream
	/// </summary>
	///
	/// <param name="InStream">The source stream to process</param>
	/// 
	/// <returns>The message hash output code</returns>
	std::vector<uint8_t> Compute(IByteStream* InStream);

	/// <summary>
	/// Process a length of bytes within the source array
	/// </summary>
	/// 
	/// <param name="Input">The source array to process</param>
	/// <param name="InOffset">The starting offset within the source array</param>
	/// <param name="Length">The number of bytes to process</param>
	/// 
	/// <returns>The message hash output code</returns>
	std::vector<uint8_t> Compute(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length);

private:

	void CalculateInterval(size_t Length);
	void CalculateProgress(size_t Length, size_t Processed);
	std::vector<uint8_t> Process(IByteStream* InStream, size_t Length);
	std::vector<uint8_t> Process(const std::vector<uint8_t> &Input, size_t InOffset, size_t Length);
};

NAMESPACE_PROCESSINGEND
#endif
