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
// Implementation Details:
// A CPU jitter implementation based on the excellent work of Stephan Müller:
// http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html
// Written by John Underhill, November 26, 2016
// Contact: develop@vtdev.com

#ifndef _CEX_CJP_H
#define _CEX_CJP_H

#include "IProvider.h"

NAMESPACE_PROVIDER

/// <summary>
/// The CPU Jitter entropy Provider (CJP).
/// <para>The jitter based entropy provider measures discreet timing differences in the nanosecond range of memory access requests and CPU execution time.
/// Because the CPU and cache memory are continuously being accessed by various operating system and application processes, small timing differences can be observed and measured using a high resolution timestamp.
/// Delays caused by events like external thread execution, branching, cache misses, and memory movement through the processor cache levels are measured, 
/// and these small differences are collected and concentrated to produce the providers output.
/// The CJP provider should not be used as the sole source of entropy for secret keys, but should be combined with other sources and concentrated to produce a key.</para>
/// </summary>
/// 
/// <example>
/// <description>Example of getting a seed value:</description>
/// <code>
/// std:vector&lt;uint8_t&gt; output(32);
/// CJP gen;
/// gen.GetBytes(output);
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description><a href="http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html">CPU Time Jitter</a> Based Non-Physical True Random Number Generator.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
/// </list> 
/// </remarks>
class CJP : public IProvider
{
private:
	const size_t ACC_LOOP_BIT_MAX = 7;
	const size_t ACC_LOOP_BIT_MIN = 0;
	const size_t CLEARCACHE = 100;
	const size_t DATA_SIZE_BITS = ((sizeof(uint64_t)) * 8);
	const size_t FOLD_LOOP_BIT_MAX = 4;
	const size_t FOLD_LOOP_BIT_MIN = 0;
	const size_t LOOP_TEST_COUNT = 300;
	const size_t MEMORY_ACCESSLOOPS = 256;
	const size_t MEMORY_BLOCKS = 512;
	const size_t MEMORY_BLOCKSIZE = 32;
	const size_t MEMORY_SIZE = (MEMORY_BLOCKS * MEMORY_BLOCKSIZE);
	const size_t OVRSMP_RATE_MAX = 128;
	const size_t OVRSMP_RATE_MIN = 1;

	bool m_enableAccess;
	bool m_enableDebias;
	bool m_isAvailable;
	uint64_t m_lastDelta;
	uint64_t m_lastDelta2;
	uint32_t m_memAccessLoops;
	uint32_t m_memBlocks;
	uint32_t m_memBlockSize;
	uint32_t m_memPosition;
	uint32_t m_memTotalSize;
	byte* m_memState;
	uint32_t m_overSampleRate;
	uint64_t m_prevTime;
	uint64_t m_rndState;
	bool m_secureCache;
	bool m_stirPool;
	uint32_t m_stuckTest;

public:

	CJP(const CJP&) = delete;
	CJP& operator=(const CJP&) = delete;
	CJP& operator=(CJP&&) = delete;

	//~~~Properties~~~//

	/// <summary>
	/// Get/Set: Enable the memory access noise source.
	/// <para>Memory access delays are injected into the random generation mechanism; enabled by default.<para>
	/// </summary>
	bool &EnableAccess() { return m_enableAccess; }

	/// <summary>
	/// Get/Set: Enable the Von Neumann debiasing extractor.
	/// <para>The default and recommended value is true, which enables the bit debiasing extractor.</para>
	/// </summary>
	bool &EnableDebias() { return m_enableDebias; }

	/// <summary>
	/// Get: The providers type name
	/// </summary>
	virtual const Enumeration::Providers Enumeral() { return Enumeration::Providers::CJP; }

	/// <summary>
	/// Get: The entropy provider is available on this system.
	/// <para>This value should be tested after class instantiation and before a request for data is made. 
	/// If the timer resolution is too small, or the provider is otherwise unavailable, requesting data will throw an exception.</para>
	/// </summary>
	virtual const bool IsAvailable() { return m_isAvailable; }

	/// <summary>
	/// Get: provider class name
	/// </summary>
	virtual const std::string Name() { return "CJP"; }

	/// <summary>
	/// Get/Set: The number of overlapping passes through the jitter entropy collector.
	/// <para>Accepted values are between 1 and 128; the default is 1.
	/// Increasing this value will increase generation times significantly.</para>
	/// </summary>
	uint32_t &OverSampleRate() { return m_overSampleRate; }

	/// <summary>
	/// Get/Set: Populate the random cache with an unused value after each generation cycle
	/// <para>Ensures memory resident state between generation calls is always an unused value.
	/// This value is true by default and a recommended option.</para>
	/// </summary>
	bool &SecureCache() { return m_secureCache; }

	//~~~Constructor~~~//

	/// <summary>
	/// Instantiate this class
	/// </summary>
	CJP()
		:
		m_enableAccess(true),
		m_enableDebias(true),
		m_isAvailable(false),
		m_lastDelta(0),
		m_lastDelta2(0),
		m_memAccessLoops(MEMORY_ACCESSLOOPS),
		m_memBlocks(MEMORY_BLOCKS),
		m_memBlockSize(MEMORY_BLOCKSIZE),
		m_memPosition(0),
		m_memTotalSize(MEMORY_SIZE),
		m_memState(0),
		m_overSampleRate(OVRSMP_RATE_MIN),
		m_prevTime(0),
		m_rndState(0),
		m_secureCache(true),
		m_stirPool(true),
		m_stuckTest(1)
	{
		if (CEX_SUPPORTED_COMPILER != 1)
			throw CryptoRandomException("CJP:Ctor", "This RNG is not supported by your compiler!");

		m_isAvailable = TimerCheck();

		if (m_isAvailable)
		{
			Detect();
			Prime();
		}
	}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~CJP()
	{
		Destroy();
	}

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Fill a buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	virtual void GetBytes(std::vector<byte> &Output);

	/// <summary>
	/// Fill the buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	virtual void GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length);

	/// <summary>
	/// Return an array with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">The size of the expected array returned</param>
	/// 
	/// <returns>An array of pseudo-random of bytes</returns>
	virtual std::vector<byte> GetBytes(size_t Length);

	/// <summary>
	/// Returns a pseudo-random unsigned 32bit integer
	/// </summary>
	virtual uint32_t Next();

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();

private:

	void AccessMemory();
	uint64_t DebiasBit();
	void Detect();
	void FoldTime(uint64_t TimeStamp, uint64_t &Folded);
	size_t Generate(std::vector<byte> &Output, size_t Offset, size_t Length);
	void Generate64();
	uint64_t GetTimeStamp();
	uint64_t MeasureJitter();
	void Prime();
	uint32_t ShuffleLoop(uint32_t LowBits, uint32_t MinShift);
	void StirPool();
	void StuckCheck(uint64_t CurrentDelta);
	bool TimerCheck();
};

NAMESPACE_PROVIDEREND
#endif
