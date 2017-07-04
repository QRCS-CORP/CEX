// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
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
// Written by John Underhill, January 21, 2015
// Updated April 21, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_DIGESTSTREAM_H
#define _CEX_DIGESTSTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "DigestFromName.h"
#include "Event.h"
#include "IByteStream.h"
#include "ParallelOptions.h"

NAMESPACE_PROCESSING

using Exception::CryptoProcessingException;
using Helper::DigestFromName;
using Enumeration::Digests;
using Routing::Event;
using IO::IByteStream;
using Digest::IDigest;
using Common::ParallelOptions;

/// <summary>
/// Digest stream helper class.
/// <para>Wraps Message Digest stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of hashing a stream:</description>
/// <code>
/// SHA512* eng = new SHA512();
/// StreamDigest sdgt(eng);
/// // get the hash code
/// hash = sdgt.Compute(Input);
/// delete eng;
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Uses any of the implemented Digests using either the IDigest interface, or a Digests enumeration member.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either of the Compute() calls.</description></item>
/// </list>
/// </remarks>
class DigestStream
{
private:

	IDigest* m_digestEngine;
	bool m_destroyEngine;
	bool m_isDestroyed = false;
	bool m_isParallel;
	size_t m_progressInterval;

public:

	DigestStream() = delete;
	DigestStream(const DigestStream&) = delete;
	DigestStream& operator=(const DigestStream&) = delete;
	DigestStream& operator=(DigestStream&&) = delete;

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	Event<int> ProgressPercent;

	//~~~Properties~~~//

	/// <summary>
	/// Get/Set: Automatic processor parallelization capable.
	/// <para>This value is true if the host supports parallelization.
	/// If the system and digest configuration both support parallelization, it can be disabled by setting this value to false.</para>
	/// </summary>
	bool IsParallel();

	/// <summary>
	/// Get/Set: Parallel block size. Must be a multiple of ParallelProfile().ParallelMinimumSize()
	/// </summary>
	size_t ParallelBlockSize();

	/// <summary>
	/// Get/Set: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state.</para>
	/// </summary>
	ParallelOptions &ParallelProfile();

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class with a digest enumeration
	/// </summary>
	/// 
	/// <param name="Digest">The digest enumeration member</param>
	/// <param name="Parallel">Instantiates the multi-threaded implementation of the digest</param>
	explicit DigestStream(Digests Digest, bool Parallel = false);

	/// <summary>
	/// Initialize the class with a digest instance
	/// <para>Digest must be fully initialized before calling this method.</para>
	/// </summary>
	/// 
	/// <param name="Digest">The initialized Digest instance</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if a null Digest is used</exception>
	explicit DigestStream(IDigest* Digest);

	/// <summary>
	/// Finalize objects
	/// </summary>
	~DigestStream();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process the entire length of the source stream
	/// </summary>
	///
	/// <param name="InStream">The source stream to process</param>
	/// 
	/// <returns>The message hash output code</returns>
	std::vector<byte> Compute(IByteStream* InStream);

	/// <summary>
	/// Process a length of bytes within the source array
	/// </summary>
	/// 
	/// <param name="Input">The source array to process</param>
	/// <param name="InOffset">The starting offset within the source array</param>
	/// <param name="Length">The number of bytes to process</param>
	/// 
	/// <returns>The message hash output code</returns>
	std::vector<byte> Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length);

private:

	void CalculateInterval(size_t Length);
	void CalculateProgress(size_t Length, size_t Processed);
	std::vector<byte> Process(IByteStream* InStream, size_t Length);
	std::vector<byte> Process(const std::vector<byte> &Input, size_t InOffset, size_t Length);
	void Destroy();
};

NAMESPACE_PROCESSINGEND
#endif
