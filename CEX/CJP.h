// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
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
// Implementation Details:
// A CPU jitter implementation based on the excellent work of Stephan Müller:
// http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html
// Written by John Underhill, November 26, 2016
// Contact: develop@vtdev.com

#ifndef CEX_CJP_H
#define CEX_CJP_H

#include "IProvider.h"

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
/// <para>The jitter based entropy provider measures discreet timing differences in the nanosecond range of memory access requests and CPU execution time.
/// Because the CPU and cache memory are continuously being accessed by various operating system and application processes, 
/// small timing differences can be observed and measured using a high-resolution timestamp.
/// Delays caused by events like external thread execution, branching, cache misses, and memory movement through the processor cache levels are measured, 
/// and these small differences are collected and concentrated to produce the providers output.
/// The CJP provider should not be used as the sole source of entropy for secret keys, but should be combined with other sources and concentrated to produce a key.</para>
/// <description>Guiding Publications::</description>
/// <list type="number">
/// <item><description><a href="http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html">CPU Time Jitter</a> Based Non-Physical True Random Number Generator.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/drafts/800-90/draft-sp800-90b.pdf">SP800-90B</a>: Recommendation for the Entropy Sources Used for Random Bit Generation.</description></item>
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips140-2/fips1402.pdf">Fips 140-2</a>: Security Requirments For Cryptographic Modules.</description></item>
/// <item><description>RFC <a href="http://www.ietf.org/rfc/rfc4086.txt">4086</a>: Randomness Requirements for Security.</description></item>
/// </list> 
/// </remarks>
class CJP final : public IProvider
{
private:

	static const uint ACC_LOOP_BIT_MAX = 7;
	static const uint ACC_LOOP_BIT_MIN = 0;
	static const std::string CLASS_NAME;
	static const uint CLEARCACHE = 100;
	static const uint DATA_SIZE_BITS = ((sizeof(ulong)) * 8);
	static const uint FOLD_LOOP_BIT_MAX = 4;
	static const uint FOLD_LOOP_BIT_MIN = 0;
	static const uint LOOP_TEST_COUNT = 300;
	static const uint MEMORY_ACCESSLOOPS = 256;
	static const uint MEMORY_BLOCKS = 512;
	static const uint MEMORY_BLOCKSIZE = 32;
	static const uint MEMORY_SIZE = (MEMORY_BLOCKS * MEMORY_BLOCKSIZE);
	static const uint OVRSMP_RATE_MAX = 128;
	static const uint OVRSMP_RATE_MIN = 1;

	bool m_enableAccess;
	bool m_enableDebias;
	bool m_hasTsc;
	bool m_isAvailable;
	ulong m_lastDelta;
	ulong m_lastDelta2;
	uint m_memAccessLoops;
	uint m_memBlocks;
	uint m_memBlockSize;
	uint m_memPosition;
	uint m_memTotalSize;
	std::vector<byte> m_memState;
	uint m_overSampleRate;
	ulong m_prevTime;
	ulong m_rndState;
	bool m_secureCache;
	bool m_stirPool;
	uint m_stuckTest;

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
	/// Read/Write: Enable the memory access noise source.
	/// <para>Memory access delays are injected into the random generation mechanism; enabled by default.</para>
	/// </summary>
	bool &EnableAccess();

	/// <summary>
	/// Read/Write: Enable the Von Neumann debiasing extractor.
	/// <para>The default and recommended value is true, which enables the bit debiasing extractor.</para>
	/// </summary>
	bool &EnableDebias();

	/// <summary>
	/// Read Only: The providers type name
	/// </summary>
	const Providers Enumeral() override;

	/// <summary>
	/// Read Only: The entropy provider is available on this system.
	/// <para>This value should be tested after class instantiation and before a request for data is made. 
	/// If the timer resolution is too small, or the provider is otherwise unavailable, requesting data will throw an exception.</para>
	/// </summary>
	const bool IsAvailable() override;

	/// <summary>
	/// Read Only: provider class name
	/// </summary>
	const std::string Name() override;

	/// <summary>
	/// Read/Write: The number of overlapping passes through the jitter entropy collector.
	/// <para>Accepted values are between 1 and 128; the default is 1.
	/// Increasing this value will increase generation times significantly.</para>
	/// </summary>
	uint &OverSampleRate();

	/// <summary>
	/// Read/Write: Populate the random cache with an unused value after each generation cycle
	/// <para>Ensures memory resident state between generation calls is always an unused value.
	/// This value is true by default and a recommended option.</para>
	/// </summary>
	bool &SecureCache();

	//~~~Public Functions~~~//

	/// <summary>
	/// Fill a buffer with pseudo-random bytes
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output) override;

	/// <summary>
	/// Fill the buffer with pseudo-random bytes using offsets
	/// </summary>
	///
	/// <param name="Output">The output array to fill</param>
	/// <param name="Offset">The starting position within the Output array</param>
	/// <param name="Length">The number of bytes to write to the Output array</param>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the random provider is not available</exception>
	void Generate(std::vector<byte> &Output, size_t Offset, size_t Length) override;

	/// <summary>
	/// Return an array with pseudo-random bytes
	/// </summary>
	/// 
	/// <param name="Length">The size of the expected array returned</param>
	/// 
	/// <returns>An array of pseudo-random of bytes</returns>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown if the random provider is not available</exception>
	std::vector<byte> Generate(size_t Length) override;

	/// <summary>
	/// Get a pseudo random unsigned 16bit integer
	/// </summary>
	/// 
	/// <returns>Random UInt16</returns>
	ushort NextUInt16() override;

	/// <summary>
	/// Get a pseudo random unsigned 32bit integer
	/// </summary>
	/// 
	/// <returns>Random 32bit integer</returns>
	uint NextUInt32() override;

	/// <summary>
	/// Get a pseudo random unsigned 64bit integer
	/// </summary>
	/// 
	/// <returns>Random 64bit integer</returns>
	ulong NextUInt64() override;

	/// <summary>
	/// Reset the internal state
	/// </summary>
	/// 
	/// <exception cref="Exception::CryptoRandomException">Thrown on entropy collection failure</exception>
	void Reset() override;

private:

	void AccessMemory();
	ulong DebiasBit();
	void Detect();
	void FoldTime(ulong TimeStamp, ulong &Folded);
	void Generate64();
	ulong GetTimeStamp();
	ulong MeasureJitter();
	void Prime();
	size_t Process(std::vector<byte> &Output, size_t Offset, size_t Length);
	size_t ShuffleLoop(uint LowBits, uint MinShift);
	void StirPool();
	void StuckCheck(ulong CurrentDelta);
	bool TimerCheck();
};

NAMESPACE_PROVIDEREND
#endif
