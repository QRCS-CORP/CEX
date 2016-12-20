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

#ifndef _CEX_MACSTREAM_H
#define _CEX_MACSTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "Event.h"
#include "IByteStream.h"
#include "IMac.h"
#include "MacDescription.h"
#include "ISymmetricKey.h"

NAMESPACE_PROCESSING

using Exception::CryptoProcessingException;
using Routing::Event;
using Key::Symmetric::ISymmetricKey;
using IO::IByteStream;
using Mac::IMac;
using Processing::MacDescription;

/// <summary>
/// MAC stream helper class.
/// <para>Wraps Message Authentication Code (MAC) stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Example of hashing a Stream:</description>
/// <code>
/// SHA256* eng = new SHA256();
/// HMAC* mac = new HMAC(eng);
/// hmac->Initialize(Key, Iv);
/// MacStream ds(mac);
/// IByteStream* ms = new MemoryStream(Input);
/// Code = ds.Compute(ms);
/// delete eng;
/// delete mac;
/// delete ms;
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Uses any of the implemented Macs using the IMac interface.</description></item>
/// <item><description>Mac must be fully initialized before passed to the constructor.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed per either Compute() calls.</description></item>
/// </list>
/// </remarks>
class MacStream
{
private:
	const size_t BUFFER_SIZE = 64 * 1024;

	size_t m_blockSize;
	bool m_destroyEngine;
	IByteStream* m_inStream;
	bool m_isDestroyed = false;
	IMac* m_macEngine;
	size_t m_progressInterval;

public:

	MacStream() = delete;
	MacStream(const MacStream&) = delete;
	MacStream& operator=(const MacStream&) = delete;
	MacStream& operator=(MacStream&&) = delete;

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	Event<int> ProgressPercent;

	/// <summary>
	/// Initialize the class with an 
	/// </summary>
	/// 
	/// <param name="Description">A MacDescription structure containing details about the Mac generator</param>
	/// <param name="MacKey">A SymmetricKey containing the Mac key and salt; note the info parameter in SymmetricKey is not used</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if an uninitialized Mac is used</exception>
	explicit MacStream(MacDescription &Description, ISymmetricKey &MacKey)
		:
		m_blockSize(0),
		m_destroyEngine(false),
		m_inStream(0),
		m_isDestroyed(false),
		m_progressInterval(0)
	{
		CreateMac(Description);
		if (m_macEngine == 0)
			throw CryptoProcessingException("MacStream:CTor", "The Mac could not be created!");

		m_macEngine->Initialize(MacKey);
		m_blockSize = m_macEngine->BlockSize();
	}

	/// <summary>
	/// Initialize the class with an initialized Mac instance
	/// </summary>
	/// 
	/// <param name="Mac">The initialized <see cref="Mac::IMac"/> instance</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if a null or uninitialized Mac is used</exception>
	explicit MacStream(IMac* Mac)
		:
		m_blockSize(Mac->BlockSize()),
		m_destroyEngine(false),
		m_inStream(0),
		m_isDestroyed(false),
		m_macEngine(Mac),
		m_progressInterval(0)
	{
		if (Mac == 0)
			throw CryptoProcessingException("MacStream:CTor", "The Mac can not be null!");
		if (!Mac->IsInitialized())
			throw CryptoProcessingException("MacStream:CTor", "The Mac is not initialized!");
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~MacStream()
	{
		Destroy();
	}

	/// <summary>
	/// Process the entire length of the Input Stream
	/// </summary>
	/// 
	/// <returns>The Mac Code</returns>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if Compute is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> Compute(IByteStream* InStream);

	/// <summary>
	/// Process a length within the Input stream using an Offset
	/// </summary>
	/// 
	/// <returns>The Mac Code</returns>
	/// <param name="Input">The Input array to process</param>
	/// <param name="InOffset">The Input array starting offset</param>
	/// <param name="Length">The number of bytes to process</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if Compute is called before Initialize(), or if Size + Offset is longer than Input stream</exception>
	std::vector<byte> Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length);

private:
	void CalculateInterval(size_t Length);
	void CalculateProgress(size_t Length, bool Completed = false);
	std::vector<byte> Process(size_t Length);
	std::vector<byte> Process(const std::vector<byte> &Input, size_t InOffset, size_t Length);
	void CreateMac(MacDescription &Description);
	void Destroy();
};

NAMESPACE_PROCESSINGEND
#endif
