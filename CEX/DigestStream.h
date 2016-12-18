// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2016 vtdev.com
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
// along with this program.If not, see <http://www.gnu.org/licenses/>.
//
// 
// Written by John Underhill, January 21, 2015
// Contact: develop@vtdev.com

#ifndef _CEX_DIGESTSTREAM_H
#define _CEX_DIGESTSTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "DigestFromName.h"
#include "Event.h"
#include "IByteStream.h"

NAMESPACE_PROCESSING

using Exception::CryptoProcessingException;
using Helper::DigestFromName;
using Enumeration::Digests;
using Routing::Event;
using IO::IByteStream;
using Digest::IDigest;

/// <summary>
/// Digest stream helper class.
/// <para>Wraps Message Digest stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of hashing a Stream:</description>
/// <code>
/// SHA512* eng = new SHA512();
/// StreamDigest dstrm(eng);
/// // get the hash code
/// hash = dstrm.ComputeHash(Input);
/// delete eng;
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Uses any of the implemented Digests using either the IDigest interface, or a Digests enumeration member.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either of the ComputeHash() calls.</description></item>
/// </list>
/// </remarks>
class DigestStream
{
private:
	const size_t BUFFER_SIZE = 64 * 1024;
	size_t m_blockSize;
	IDigest* m_digestEngine;
	bool m_destroyEngine;
	IByteStream* m_inStream;
	bool m_isDestroyed = false;
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

	/// <summary>
	/// Initialize the class with a digest instance
	/// <para>Digest must be fully initialized before calling this method.</para>
	/// </summary>
	/// 
	/// <param name="Digest">The initialized Digest instance</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if a null Digest is used</exception>
	explicit DigestStream(IDigest* Digest)
		:
		m_blockSize(Digest->BlockSize()),
		m_destroyEngine(false),
		m_digestEngine(Digest),
		m_inStream(0),
		m_isDestroyed(false),
		m_progressInterval(0)
	{
		if (Digest == 0)
			throw CryptoProcessingException("DigestStream:CTor", "The Digest can not be null!");
	}

	/// <summary>
	/// Initialize the class with a digest enumeration
	/// </summary>
	/// 
	/// <param name="Digest">The digest enumeration member</param>
	explicit DigestStream(Digests Digest)
		:
		m_destroyEngine(true),
		m_inStream(0),
		m_isDestroyed(false),
		m_progressInterval(0)
	{
		m_digestEngine = DigestFromName::GetInstance(Digest);
		m_blockSize = m_digestEngine->BlockSize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~DigestStream()
	{
		Destroy();
	}

	/// <summary>
	/// Process the entire length of the Input Stream
	/// </summary>
	/// 
	/// <returns>The Message Digest</returns>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> ComputeHash(IByteStream* InStream);

	/// <summary>
	/// Process a length within the Input stream using an Offset
	/// </summary>
	/// 
	/// <returns>The Message Digest</returns>
	/// <param name="Input">The Input array to process</param>
	/// <param name="InOffset">The Input array starting offset</param>
	/// <param name="Length">The number of bytes to process</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if ComputeHash is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> ComputeHash(const std::vector<byte> &Input, size_t InOffset, size_t Length);

private:
	void CalculateInterval(size_t Length);
	void CalculateProgress(size_t Length, bool Completed = false);
	std::vector<byte> Compute(size_t Length);
	std::vector<byte> Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length);
	void Destroy();
};

NAMESPACE_PROCESSINGEND
#endif
