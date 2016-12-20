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
// Principal Algorithms:
// An implementation of the SHA-3 digest based on Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. 
// SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.
// 
// Implementation Details:
// An implementation of the SHA-3 digest with a 256 bit return size. 
// Written by John Underhill, September 19, 2014
// Contact: develop@vtdev.com

#ifndef _CEX_KECCAK256_H
#define _CEX_KECCAK256_H

#include "IDigest.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the SHA-3 Keccak digest
/// </summary>
///
/// <example>
/// <description>Example using the Compute method:</description>
/// <code>
/// Keccak256 digest;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// digest.Compute(Input, hash);
/// </code>
/// </example>
///
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Hash sizes are 28, 32, and 36 bytes (224, 256, and 288 bits).</description></item>
/// <item><description>Block sizes are 144, 128, and 136 bytes (1152, 1024, 1088 bits).</description></item>
/// <item><description>Use the <see cref="BlockSize"/> property to determine block sizes at runtime.</description></item>
/// <item><description>The <see cref="Compute(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
/// 
/// <list type="number">
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.</description></item>
/// <item><description>SHA3 <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf">Keccak Slides</a>.</description></item>
/// <item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
/// </list>
/// </remarks>
class Keccak256 : public IDigest
{
private:

	size_t m_blockSize;
	std::vector<byte> m_buffer;
	size_t m_bufferIndex;
	size_t m_digestSize;
	bool m_isDestroyed;
	std::vector<ulong> m_state;

public:

	Keccak256(const Keccak256&) = delete;
	Keccak256& operator=(const Keccak256&) = delete;
	Keccak256& operator=(Keccak256&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual size_t BlockSize() { return m_blockSize; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual size_t DigestSize() { return m_digestSize; }

	/// <summary>
	/// Get: The digests type name
	/// </summary>
	virtual Digests Enumeral() { return Digests::Keccak256; }

	/// <summary>
	/// Get: The digests class name
	/// </summary>
	virtual const std::string Name() { return "Keccak256"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the digest
	/// </summary>
	///
	/// <param name="DigestSize">Digest return size in bits</param>
	explicit Keccak256(int DigestSize = 256)
		:
		m_isDestroyed(false),
		m_blockSize(0),
		m_buffer(0),
		m_bufferIndex(0),
		m_digestSize(0),
		m_state(25, 0)
	{
		// test for legal sizes; default at 256
		if (DigestSize == 224)
			m_digestSize = 224 / 8;
		else if (DigestSize == 288)
			m_digestSize = 288 / 8;
		else
			m_digestSize = 256 / 8;

		m_blockSize = 200 - (m_digestSize * 2);

		Initialize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Keccak256()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Update the buffer
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">Amount of data to process in bytes</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the input buffer is too short</exception>
	virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

	/// <summary>
	/// Get the Hash value
	/// </summary>
	/// 
	/// <param name="Input">Input data</param>
	/// <param name="Output">The hash output value array</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Do final processing and get the hash value
	/// </summary>
	/// 
	/// <param name="Output">The Hash output value array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <returns>Size of Hash value</returns>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output buffer is too short</exception>
	virtual size_t DoFinal(std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the digest with a single byte
	/// </summary>
	///
	/// <param name="Input">Input byte</param>
	virtual void Update(byte Input);

private:
	void Initialize();
};

NAMESPACE_DIGESTEND
#endif
