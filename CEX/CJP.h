// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
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
// Updated by January 28, 2019
// Contact: develop@vtdev.com

#ifndef CEX_CJP_H
#define CEX_CJP_H

#include "ProviderBase.h"

NAMESPACE_PROVIDER

/// <summary>
/// The CPU Jitter entropy Provider
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std::vector&lt;byte&gt; output(32);
/// CJP gen;
/// gen.Generate(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <para>The jitter based entropy provider measures discreet timing differences in the nanosecond range of memory access requests and CPU execution time. \n 
/// Because the CPU and cache memory are continuously being accessed by various operating system and application processes, 
/// small timing differences can be observed and measured using a high-resolution timestamp. \n 
/// Delays caused by events like external thread execution, branching, cache misses, and memory movement through the processor cache levels are measured, 
/// and these small differences are collected and concentrated to produce the providers output. \n 
/// The CJP provider should not be used as the sole source of entropy for secret keys, but should be combined with other sources and concentrated to produce a key, such as the auto-seed collection provider ACP.</para>
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description><a href="http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html">CPU Time Jitter</a> Based Non-Physical True Random Number Generator.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
/// </list> 
/// </remarks>
class CJP final : public ProviderBase
{
private:

	static const size_t ACC_LOOP_BIT_MAX = 7;
	static const size_t ACC_LOOP_BIT_MIN = 0;
	static const size_t CLEARCACHE = 100;
	static const size_t DATA_SIZE_BITS = ((sizeof(ulong)) * 8);
	static const size_t FOLD_LOOP_BIT_MAX = 4;
	static const size_t FOLD_LOOP_BIT_MIN = 0;
	static const size_t LOOP_TEST_COUNT = 300;
	static const size_t MEMORY_ACCESSLOOPS = 256;
	static const size_t MEMORY_BLOCKS = 512;
	static const size_t MEMORY_BLOCKSIZE = 32;
	static const size_t MEMORY_SIZE = (MEMORY_BLOCKS * MEMORY_BLOCKSIZE);
	static const size_t OVRSMP_RATE_MAX = 128;
	static const size_t OVRSMP_RATE_MIN = 1;
	static const bool TIMER_HAS_TSC;

	struct JitterState;

#if defined(CEX_FIPS140_ENABLED)
	ProviderSelfTest m_pvdSelfTest;
#endif
	std::unique_ptr<JitterState> m_pvdState;

public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CJP(const CJP&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CJP& operator=(const CJP&) = delete;

	/// <summary>
	/// Constructor: instantiate this class
	/// </summary>
	CJP();

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	~CJP() override;

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: The number of overlapping passes through the jitter entropy collector.
	/// <para>Accepted values are between 1 and 128; the default is 1.
	/// Increasing this value will increase generation times significantly.</para>
	/// </summary>
	size_t &OverSampleRate();

	/// <summary>
	/// Read/Write: Populate the random cache with an unused value after each generation cycle
	/// <para>Ensures memory resident state between generation calls is always an unused value.
	/// This value is true by default and a recommended option.</para>
	/// </summary>
	bool &SecureCache();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output) override;

	/// <summary>
	/// Fill a standard vector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination standard vector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Fill a SecureVector with pseudo-random bytes using offset and length parameters
	/// </summary>
	///
	/// <param name="Output">The destination SecureVector to fill</param>
	/// <param name="Offset">The starting position within the destination vector</param>
	/// <param name="Length">The number of bytes to write to the destination vector</param>
	/// 
	/// <exception cref="CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(SecureVector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	/// 
	/// <exception cref="CryptoRandomException">Thrown on entropy collection failure</exception>
	void Reset() override;

private:

	bool FipsTest();
	static void FoldTime(std::unique_ptr<JitterState> &State, ulong TimeStamp);
	static void GetRandom(std::unique_ptr<JitterState> &State);
	static void GetRandom(std::unique_ptr<JitterState> &State, byte* Output, size_t Length);
	static ulong GetTime();
	static bool MeasureJitter(std::unique_ptr<JitterState> &State);
	static void MemoryJitter(std::unique_ptr<JitterState> &State);
	static std::unique_ptr<JitterState> Prime();
	static size_t ShuffleLoop(std::unique_ptr<JitterState> &State, size_t LowBits, size_t MinShift);
	static bool StuckCheck(std::unique_ptr<JitterState> &State, ulong CurrentDelta);
	static bool TimerCheck(std::unique_ptr<JitterState> &State);
};

NAMESPACE_PROVIDEREND
#endif
