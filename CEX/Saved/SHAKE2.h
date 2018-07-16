
#ifndef CEX_SHAKE2_H
#define CEX_SHAKE2_H

//#include "BlakeParams.h"
#include "IDigest.h"
#include "ISymmetricKey.h"
#include "ShakeModes.h"
#include "Keccak.h"

NAMESPACE_DIGEST

using Key::Symmetric::ISymmetricKey;
using Enumeration::ShakeModes;

/// <summary>
/// An implementation of the Blake2S and Blake2SP digests with a 256 bit digest output size
/// </summary> 
/// 
/// <example>
/// <description>Example using the Compute method:</description>
/// <para>Use the Compute method for small to medium data sizes</para>
/// <code>
/// Blake256 dgt;
/// std:vector&lt;byte&gt; hash(dgt.DigestSize(), 0);
/// // compute a hash
/// dgt.Compute(input, hash);
/// </code>
/// </example>
///
/// <example>
/// <description>Use the Update method for large data sizes:</description>
/// <code>
/// Blake256 dgt;
/// std:vector&lt;byte&gt; hash(dgt.DigestSize(), 0);
/// int64_t len = (int64_t)input.size();
///
/// // update blocks
/// while (len > dgt.DigestSize())
/// {
///		dgt.Update(input, offset, len);
///		offset += dgt.DigestSize();
///		len -= dgt.DigestSize();
/// }
///
/// if (len > 0)
///		dgt.Update(input, offset, len);
///
/// dgt.Finalize(hash, 0);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>Algorithm is selected through the constructor (2S or 2SP), parallel version is selected through either the Parallel flag, or via the BlakeParams ThreadCount() configuration parameter.</description></item>
/// <item><description>Parallel and sequential algorithms (Blake2S or Blake2SP) produce different digest outputs, this is expected.</description></item>
/// <item><description>Sequential Block size is 64 bytes, (512 bits), but smaller or larger blocks can be processed, for best performance, align message input to a multiple of the internal block size.</description></item>
/// <item><description>Parallel Block input size to the Update function should be aligned to a multiple of ParallelMinimumSize() for best performance.</description></item>
/// <item><description>Best performance for parallel mode is to use a large input block size to minimize parallel loop creation cost, block size should be in a range of 32KiB to 25MiB.</description></item>
/// <item><description>The number of threads used in parallel mode can be user defined through the BlakeParams->ThreadCount property to any even number of threads; note that hash value will change with threadcount.</description></item>
/// <item><description>Digest output size is fixed at 32 bytes, (256 bits).</description></item>
/// <item><description>The <see cref="Compute(byte[])"/> method wraps the <see cref="Update(byte[], size_t, size_t)"/> and Finalize methods</description>/></item>
/// <item><description>The <see cref="Finalize(byte[], size_t)"/> method resets the internal state.</description></item>
/// <item><description>Optional intrinsics are runtime enabled automatically based on cpu support.</description></item>
/// <item><description>SIMD implementation requires compilation with SSE3 or higher.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>Blake2 <a href="https://blake2.net/">Homepage</a>.</description></item>
/// <item><description>Blake2 on <a href="https://github.com/BLAKE2/BLAKE2">Github</a>.</description></item>
/// <item><description>Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.</description></item>
/// <item><description>NIST <a href="https://131002.net/blake">SHA3 Proposal Blake</a>.</description></item>
/// <item><description>NIST <a href="http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf">SHA3: Third-Round Report</a> of the SHA-3 Cryptographic Hash Algorithm Competition.</description></item>
/// <item><description>SHA3 Submission in C: <a href="https://131002.net/blake/blake_ref.c">blake_ref.c</a>.</description></item>
/// </list>
/// </remarks>
class SHAKE2 //final : public IDigest
{
private:

	size_t m_bitRate;
	std::array<ulong, 25> m_kdfState;
	ShakeModes m_kdfMode;
	std::array<ulong, 25> m_dgtState;
	size_t m_msgPosition;
	std::array<byte, 200> m_msgBuffer;
	size_t m_msgLength;

public:

	SHAKE2(ShakeModes Mode)
		: 
		m_bitRate(1600 - (Mode == ShakeModes::SHAKE128 ? 256 : 512)), 
		m_kdfMode(Mode),
		m_msgLength(0),
		m_msgPosition(0)
	{
		reset();
	}

	const size_t BlockSize()
	{
		return m_bitRate / 8;
	}

	// Old //

	void reset()
	{
		std::memset(&m_kdfState[0], 0, m_kdfState.size() * sizeof(ulong));
		std::memset(&m_dgtState[0], 0, m_dgtState.size() * sizeof(ulong));
		m_dgtState[1] = 0xFFFFFFFFFFFFFFFFULL;
		m_dgtState[2] = 0xFFFFFFFFFFFFFFFFULL;
		m_dgtState[8] = 0xFFFFFFFFFFFFFFFFULL;
		m_dgtState[12] = 0xFFFFFFFFFFFFFFFFULL;
		m_dgtState[17] = 0xFFFFFFFFFFFFFFFFULL;
		m_dgtState[20] = 0xFFFFFFFFFFFFFFFFULL;

		m_msgPosition = 0;
	}

	void absorb(const uint8_t input[], size_t length)
	{
		while (length > 0)
		{
			size_t to_take = std::min(length, m_bitRate / 8 - m_msgPosition);

			length -= to_take;

			while (to_take && m_msgPosition % 8)
			{
				m_kdfState[m_msgPosition / 8] ^= static_cast<uint64_t>(input[0]) << (8 * (m_msgPosition % 8));

				++m_msgPosition;
				++input;
				--to_take;
			}

			while (to_take && to_take % 8 == 0)
			{
				m_kdfState[m_msgPosition / 8] ^= load_le<uint64_t>(input, 0);
				m_msgPosition += 8;
				input += 8;
				to_take -= 8;
			}

			while (to_take)
			{
				m_kdfState[m_msgPosition / 8] ^= static_cast<uint64_t>(input[0]) << (8 * (m_msgPosition % 8));

				++m_msgPosition;
				++input;
				--to_take;
			}

			if (m_msgPosition == m_bitRate / 8)
			{
				permute(m_kdfState);
				m_msgPosition = 0;
			}
		}
	} 
	  // 938285942917097860, 13278690460726677960, 0, ...
	  // 938285942917097860, 13278690460726677960, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...[20] 9223372036854775808
	  // 10125282692782987653, 14272605148073806409, 18381153753321745956, 5912912542345646481, ...

	void add_data(const uint8_t input[], size_t length)
	{
		absorb(input, length);
	}

	void expand(uint8_t output[], size_t output_length)
	{
		size_t Si = 0;

		for (size_t i = 0; i != output_length; ++i)
		{
			if (i > 0)
			{
				if (i % (m_bitRate / 8) == 0)
				{
					permute(m_kdfState);
					Si = 0;
				}
				else if (i % 8 == 0)
				{
					Si += 1;
				}
			}

			output[i] = get_byte(7 - (i % 8), m_kdfState[Si]);
		}
	}

	void final_result(uint8_t output[], size_t length)
	{
		std::vector<uint8_t> padding(m_bitRate / 8 - m_msgPosition);

		padding[0] = 0x1F;
		padding[padding.size() - 1] |= 0x80;

		add_data(padding.data(), padding.size());

		expand(output, length);

		reset();
	}

	template<typename T> inline uint8_t get_byte(size_t byte_num, T input)
	{
		return static_cast<uint8_t>(input >> (((~byte_num)&(sizeof(T) - 1)) << 3));
	}

	template<typename T>
	inline T load_le(const uint8_t in[], size_t off)
	{
		in += off * sizeof(T);
		T out = 0;
		for (size_t i = 0; i != sizeof(T); ++i)
			out = (out << 8) | in[sizeof(T) - 1 - i];

		return out;
	}

	void permute(std::array<ulong, 25> &State)
	{
		State[1] ^= 0xFFFFFFFFFFFFFFFFULL;
		State[2] ^= 0xFFFFFFFFFFFFFFFFULL;
		State[8] ^= 0xFFFFFFFFFFFFFFFFULL;
		State[12] ^= 0xFFFFFFFFFFFFFFFFULL;
		State[17] ^= 0xFFFFFFFFFFFFFFFFULL;
		State[20] ^= 0xFFFFFFFFFFFFFFFFULL;

		Keccak::Permute24(State);

		State[1] = ~State[1];
		State[2] = ~State[2];
		State[8] = ~State[8];
		State[12] = ~State[12];
		State[17] = ~State[17];
		State[20] = ~State[20];
	}
};

NAMESPACE_DIGESTEND
#endif