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
// An implementation of the SHA-3 digest with a 512 bit return size. 
// Written by John Underhill, September 19, 2014
// Contact: develop@vtdev.com
//
#ifndef _CEX_KECCAK512_H
#define _CEX_KECCAK512_H

#include "IDigest.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the SHA-3 Keccak digest
/// </summary>
///
/// <example>
/// <description>Example using an <c>IDigest</c> interface:</description>
/// <code>
/// Keccak512 digest;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// digest.Compute(Input, hash);
/// </code>
/// </example>
///
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Hash sizes are 48 and 64 bytes (384 and 512 bits).</description></item>
/// <item><description>Block sizes are 104, and 72 bytes (832, 576 bits).</description></item>
/// <item><description>Use the <see cref="BlockSize"/> property to determine block sizes at runtime.</description></item>
/// <item><description>The <see cref="Compute(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], int, int)"/> and DoFinal methods.</description>/></item>
/// <item><description>The <see cref="DoFinal(byte[], int)"/> method resets the internal state.</description></item>
/// </list>
///
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>SHA3 <a href="http://keccak.noekeon.org/Keccak-submission-3.pdf">Keccak Submission</a>.</description></item>
/// <item><description>SHA3 <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf">Keccak Slides</a>.</description></item>
/// <item><description>SHA3 <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
/// </list>
/// </remarks>
class Keccak512 : public IDigest
{
private:

	size_t m_blockSize;
	std::vector<byte> m_buffer;
	size_t m_bufferIndex;
	size_t m_digestSize;
	bool m_isDestroyed;
	std::vector<ulong> m_state;

public:

	Keccak512(const Keccak512&) = delete;
	Keccak512& operator=(const Keccak512&) = delete;
	Keccak512& operator=(Keccak512&&) = delete;

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
	virtual Digests Enumeral() { return Digests::Keccak512; }

	/// <summary>
	/// Get: The digests class name
	/// </summary>
	virtual const std::string Name() { return "Keccak512"; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the digest
	/// </summary>
	///
	/// <param name="DigestSize">Digest return size in bits</param>
	explicit Keccak512(int DigestSize = 512)
		:
		m_blockSize(0),
		m_buffer(0),
		m_bufferIndex(0),
		m_isDestroyed(false),
		m_digestSize(0),
		m_state(25, 0)
	{
		// test for legal sizes; default at 512
		if (DigestSize == 384)
			m_digestSize = 384 / 8;
		else
			m_digestSize = 512 / 8;

		m_blockSize = 200 - (m_digestSize * 2);

		Initialize();
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~Keccak512()
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
