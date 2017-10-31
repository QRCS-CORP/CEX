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

#ifndef CEX_MACSTREAM_H
#define CEX_MACSTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "Event.h"
#include "IByteStream.h"
#include "IMac.h"
#include "ISymmetricKey.h"
#include "MacDescription.h"
#include "SymmetricKeySize.h"

NAMESPACE_PROCESSING

using Exception::CryptoProcessingException;
using Routing::Event;
using Key::Symmetric::ISymmetricKey;
using IO::IByteStream;
using Mac::IMac;
using Key::Symmetric::SymmetricKeySize;

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

	std::unique_ptr<IMac> m_macEngine;
	bool m_destroyEngine;
	bool m_isDestroyed;
	bool m_isInitialized;
	size_t m_progressInterval;

public:

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	Event<int> ProgressPercent;

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	MacStream(const MacStream&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	MacStream& operator=(const MacStream&) = delete;

	/// <summary>
	/// Default constructor: default is restricted, this function has been deleted
	/// </summary>
	MacStream() = delete;

	/// <summary>
	/// Initialize the class with a MacDescription
	/// </summary>
	/// 
	/// <param name="Description">A MacDescription structure containing details about the Mac generator</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if invalid parameters are used</exception>
	explicit MacStream(MacDescription &Description);

	/// <summary>
	/// Initialize the class with a Mac instance
	/// </summary>
	/// 
	/// <param name="Mac">The <see cref="Mac::IMac"/> instance</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if invalid parameters are used</exception>
	explicit MacStream(IMac* Mac);

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~MacStream();

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The supported key sizes for the selected mac configuration
	/// </summary>
	const std::vector<SymmetricKeySize> LegalKeySizes();

	//~~~Public Functions~~~//

	/// <summary>
	/// Process the entire length of the source stream
	/// </summary>
	///
	/// <param name="InStream">The source stream to process</param>
	/// 
	/// <returns>The Mac output code</returns>
	std::vector<byte> Compute(IByteStream* InStream);

	/// <summary>
	/// Process a length of bytes within the source array
	/// </summary>
	/// 
	/// <param name="Input">The source array to process</param>
	/// <param name="InOffset">The starting offset within the source array</param>
	/// <param name="Length">The number of bytes to process</param>
	/// 
	/// <returns>The Mac output code</returns>
	std::vector<byte> Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Initialize the MAC generator with a SymmetricKey key container.
	/// <para>Uses a key array to initialize the MAC.
	/// The key size should be one of the LegalKeySizes.</para>
	/// </summary>
	/// 
	/// <param name="KeyParams">A SymmetricKey key container class</param>
	/// 
	/// <exception cref="Exception::CryptoProcessingException">Thrown if invalid key sizes are used</exception>
	void Initialize(ISymmetricKey &KeyParams);

private:

	void CalculateInterval(size_t Length);
	void CalculateProgress(size_t Length, size_t Processed);
	void Destroy();
	std::vector<byte> Process(IByteStream* InStream, size_t Length);
	std::vector<byte> Process(const std::vector<byte> &Input, size_t InOffset, size_t Length);
};

NAMESPACE_PROCESSINGEND
#endif
