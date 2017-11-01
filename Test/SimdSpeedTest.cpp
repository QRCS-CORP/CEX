#include "SimdSpeedTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
#if defined(__AVX512__)
#	include "../CEX/UInt512.h"
#elif defined(__AVX2__)
#	include "../CEX/UInt256.h"
#elif defined(__AVX__)
#	include "../CEX/UInt128.h"
#endif

namespace Test
{
	using Utility::MemUtils;
	using Utility::IntUtils;

#if defined(__AVX512__)
	using Numeric::UInt512;
#elif defined(__AVX2__)
	using Numeric::UInt256;
#elif defined(__AVX__)
	using Numeric::UInt128;
#endif

	const std::string SimdSpeedTest::DESCRIPTION = "MemUtils test; tests output and speed of parallelized memory functions.";
	const std::string SimdSpeedTest::FAILURE = "FAILURE! ";
	const std::string SimdSpeedTest::MESSAGE = "All SIMD tests have executed succesfully.";
#if defined(_DEBUG)
	const std::string SimdSpeedTest::TESTSIZE = "100 Megabytes";
#else
	const std::string SimdSpeedTest::TESTSIZE = "1 Gigabyte";
#endif

	SimdSpeedTest::SimdSpeedTest()
		:
		m_hasAVX(false),
		m_hasAVX2(false),
		m_hasAVX512(false),
		m_progressEvent()
	{
	}

	SimdSpeedTest::~SimdSpeedTest()
	{
	}

	const std::string SimdSpeedTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SimdSpeedTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SimdSpeedTest::Run()
	{
		try
		{
			Initialize();

#if defined(_DEBUG)
			const size_t SMPLEN = MB100;
#else
			const size_t SMPLEN = GB1;
#endif
			OnProgress(std::string(""));
			OnProgress(std::string("### SIMD MEMORY SPEED TESTS ###"));
			OnProgress(std::string("### Uses the highest available intrinsics instruction set AVX, AVX2, or AVX512"));
			OnProgress(std::string("### Measures the performance of sequential to parallel memory operations: copy, set, clear, and xor"));
			OnProgress(std::string("### The Block operations use a 512 block of bytes to perform the operations"));
			OnProgress(std::string("### The Vectorized operations use the SIMD byte size (128/256/512) as the buffer size"));
#if defined(__AVX512__)
			OnProgress(std::string("### Highest detected SIMD instruction set is AVX512 ###"));
#elif defined(__AVX2__)
			OnProgress(std::string("### Highest detected SIMD instruction set is AVX2 ###"));
#elif defined(__AVX__)
			OnProgress(std::string("### Highest detected SIMD instruction set is AVX ###"));
#endif
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Large Block Clear Functions***"));
			ClearBlockSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Vectorized Clear Functions***"));
			ClearVectorSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Large Block Memory Copy Functions***"));
			//for (size_t i = 0; i < 10; ++i)
			CopyBlockSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Vector Aligned Block Memory Copy Functions***"));
			CopyVectorSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Large Block Memset Functions***"));
			SetBlockSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Vectorized Memset Functions***"));
			SetVectorSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Large Block XOR Functions***"));
			XorBlockSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			OnProgress(std::string("***Testing Vectorized XOR Functions***"));
			XorVectorSpeed(SMPLEN, 10);
			OnProgress(std::string(""));

			return MESSAGE;
		}
		catch (std::exception const &ex)
		{
			return FAILURE + " : " + ex.what();
		}
		catch (...)
		{
			return FAILURE + " : Unknown Error";
		}
	}

	void SimdSpeedTest::ClearBlockSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(0);
		std::vector<byte> buffer2(0);
		uint64_t blkCtr = 0;
		std::string glen = "";
		uint64_t start = 0;
		uint64_t dur = 0;

		// Large Block Clear
#if defined(__AVX__)

		glen = "SpeedTest: BLOCK CLEAR " + TESTSIZE;
		// sequential clear: 512 byte buffers
		OnProgress(std::string(glen + " using 512 byte buffers with sequential clear "));
		buffer1.resize(B512, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0x0, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));

		// highest available simd clear
		glen = "SpeedTest: CLEAR " + TESTSIZE;
		OnProgress(std::string(glen + " using 512 byte buffers with SIMD vectorized clear "));
		buffer2.resize(B512, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::Clear(buffer2, 0, buffer2.size());
				blkCtr += buffer2.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));
#endif
	}

	void SimdSpeedTest::ClearVectorSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(0);
		std::vector<byte> buffer2(0);
		uint64_t blkCtr = 0;
		std::string glen = "";
		uint64_t start = 0;
		uint64_t dur = 0;

		// Vector Aligned Clear
#if defined(__AVX512__)

		// sequential memset: 64 byte buffers
		glen = "SpeedTest: VECTOR CLEAR " + TESTSIZE;
		OnProgress(std::string(glen + " using 64 byte buffers with sequential clear "))
		buffer1.resize(64, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0x0, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));

		// simd256 memset
		OnProgress(std::string(glen + " using 64 byte buffers with AVX512 vectorized clear "));
		buffer2.resize(64, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::CLEAR128(buffer2, 0);
				blkCtr += buffer2.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));

#elif defined(__AVX2__)
		// sequential clear: 32 byte buffers
		glen = "SpeedTest: VECTOR CLEAR " + TESTSIZE;
		OnProgress(std::string(glen + " using 32 byte buffers with sequential clear "));
		buffer1.resize(32, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0x0, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));

		// simd256 clear
		OnProgress(std::string(glen + " using 32 byte buffers with AVX2 vectorized clear "));
		buffer2.resize(32, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::CLEAR256(buffer2, 0);
				blkCtr += buffer2.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));

#elif defined(__AVX__)
		glen = "SpeedTest: VECTOR CLEAR " + TESTSIZE;
		// sequential memset: 16 byte buffers
		OnProgress(std::string(glen + " using 16 byte buffers with sequential clear "));
		buffer1.resize(16, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0x0, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));

		// simd128 clear
		glen = "SpeedTest: simd128 clear " + TESTSIZE;
		OnProgress(std::string(glen + " using 16 byte buffers with AVX vectorized clear "));
		buffer2.resize(16, (byte)0xff);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::CLEAR128(buffer2, 0);
				blkCtr += buffer2.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Cleared "));
#endif
	}

	void SimdSpeedTest::CopyBlockSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(B512, (byte)0xff);
		std::vector<byte> buffer2(B512);
		std::vector<byte> buffer3(B512, (byte)0xff);
		std::vector<byte> buffer4(B512);
		uint64_t blkCtr = 0;
		std::string glen = "SpeedTest: BLOCK COPY " + TESTSIZE;
		uint64_t start = 0;
		uint64_t dur = 0;

		// Large Block Copy
#if defined(__AVX__)
		// sequential copy: 1KB byte buffers
		OnProgress(std::string(glen + " using 512 byte buffers with sequential memcpy: "));
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memcpy(&buffer2[0], &buffer1[0], buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));

		// highest available simd copy
		OnProgress(std::string(glen + " using 512 byte buffers with SIMD vectorized memcpy "));
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::Copy(buffer3, 0, buffer4, 0, buffer4.size());
				blkCtr += buffer4.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));
#endif
	}

	void SimdSpeedTest::CopyVectorSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(0);
		std::vector<byte> buffer2(0);
		std::vector<byte> buffer3(0);
		std::vector<byte> buffer4(0);
		uint64_t blkCtr = 0;
		std::string glen = "SpeedTest: VECTOR COPY " + TESTSIZE;
		uint64_t start = 0;
		uint64_t dur = 0;

		// Vector Aligned Copy
#if defined(__AVX512__)
		OnProgress(std::string(glen + " using 64 byte buffers with sequential copy "));
		// sequential copy: 64 byte buffers
		buffer1.resize(64, (byte)0xff);
		buffer2.resize(64);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memcpy(&buffer2[0], &buffer1[0], buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));

		// simd512 memcpy
		OnProgress(std::string(glen + " using 64 byte buffers with AVX512 vectorized copy "));
		buffer3.resize(64, (byte)0xff);
		buffer4.resize(64);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::COPY512(buffer3, 0, buffer4, 0);
				blkCtr += buffer3.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));

#elif defined(__AVX2__)
		OnProgress(std::string(glen + " using 32 byte buffers with sequential copy "));
		// sequential copy: 32 byte buffers
		buffer1.resize(32, (byte)0xff);
		buffer2.resize(32);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memcpy(&buffer2[0], &buffer1[0], buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));

		// simd256 memcpy
		OnProgress(std::string(glen + " using 32 byte buffers with AVX2 vectorized memcpy "));
		buffer3.resize(32, (byte)0xff);
		buffer4.resize(32);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::COPY256(buffer3, 0, buffer4, 0);
				blkCtr += buffer3.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));

#elif defined(__AVX__)
		OnProgress(std::string(glen + " using 16 byte buffers with sequential memcpy: "));
		// sequential copy: 16 byte buffers
		buffer1.resize(16, (byte)0xff);
		buffer2.resize(16);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memcpy(&buffer2[0], &buffer1[0], buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));

		// simd128
		OnProgress(std::string(glen + " using 16 byte buffers with AVX vectorized memcpy "));
		blkCtr = 0;
		buffer3.resize(16, (byte)0xff);
		buffer4.resize(16);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::COPY128(buffer3, 0, buffer4, 0);
				blkCtr += buffer3.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Copied "));
#endif
	}

	void SimdSpeedTest::SetBlockSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(0);
		std::vector<byte> buffer2(0);
		uint64_t blkCtr = 0;
		std::string glen = "SpeedTest: BLOCK SET " + TESTSIZE;
		uint64_t start = 0;
		uint64_t dur = 0;

		// Large Block Memset
#if defined(__AVX__)
		OnProgress(std::string(glen + " using 512 byte buffers with sequential memset "));
		// sequential memset: 512 byte buffers
		buffer1.resize(B512);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0xff, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));

		// highest available simd memset
		OnProgress(std::string(glen + " using 512 byte buffers with SIMD vectorized memset "));
		buffer2.resize(B512);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::SetValue(buffer2, 0, buffer2.size(), (byte)0xff);
				blkCtr += buffer2.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));
#endif

	}

	void SimdSpeedTest::SetVectorSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(0);
		std::vector<byte> buffer2(0);
		uint64_t blkCtr = 0;
		std::string glen = "SpeedTest: VECTOR SET " + TESTSIZE;
		uint64_t start = 0;
		uint64_t dur = 0;

		// Vector Aligned Memset
#if defined(__AVX512__)
		// sequential memset: 64 byte buffers
		OnProgress(std::string(glen + " using 64 byte buffers with sequential memset "))
		buffer1.resize(64);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0xff, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));

		// simd512 memset
		OnProgress(std::string(glen + " using 64 byte buffers with AVX512 vectorized memset "));
		buffer2.resize(64);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::SETVAL512(buffer2, 0, (byte)0xff);
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));

#elif defined(__AVX2__)
		// sequential memset: 32 byte buffers
		OnProgress(std::string(glen + " using 32 byte buffers with sequential memset "));
		buffer1.resize(32);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0xff, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));

		// simd256 memset
		OnProgress(std::string(glen + " using 32 byte buffers with AVX2 vectorized memset "));
		buffer2.resize(32);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::SETVAL256(buffer2, 0, (byte)0xff);
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));

#elif defined(__AVX__)
		// sequential memset: 16 byte buffers
		OnProgress(std::string(glen + " using 16 byte buffers with sequential memset "));
		buffer1.resize(16);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				std::memset(&buffer1[0], (byte)0xff, buffer1.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));

		// simd128 memset
		glen = "SpeedTest: memset " + TESTSIZE;
		OnProgress(std::string(glen + " using 16 byte buffers with AVX vectorized memset "));
		buffer2.resize(16);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::SETVAL128(buffer2, 0, (byte)0xff);
				blkCtr += buffer2.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("Set "));
#endif
	}

	void SimdSpeedTest::XorBlockSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(0);
		std::vector<byte> buffer2(0);
		std::vector<byte> buffer3(0);
		std::vector<byte> buffer4(0);
		uint64_t blkCtr = 0;
		std::string glen = "SpeedTest: BLOCK XOR " + TESTSIZE;
		uint64_t start = 0;
		uint64_t dur = 0;

		// Large Block XOR
#if defined(__AVX__)
		// sequential memset: 512 byte buffers
		OnProgress(std::string(glen + " using 512 byte buffers with sequential XOR "));
		buffer1.resize(B512, (byte)0x7);
		buffer2.resize(B512, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				for (size_t j = 0; j < buffer1.size(); ++j)
				{
					buffer2[j] ^= buffer1[j];
				}
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));

		// highest available simd xor
		OnProgress(std::string(glen + " using 512 byte buffers with SIMD vectorized XOR "));
		buffer3.resize(B512, (byte)0x7);
		buffer4.resize(B512, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::XorBlock(buffer3, 0, buffer4, 0, buffer3.size());
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));
#endif
	}

	void SimdSpeedTest::XorVectorSpeed(uint64_t Length, size_t Loops)
	{
		std::vector<byte> buffer1(0);
		std::vector<byte> buffer2(0);
		std::vector<byte> buffer3(0);
		std::vector<byte> buffer4(0);
		uint64_t blkCtr = 0;
		std::string glen = "SpeedTest: VECTOR XOR " + TESTSIZE;
		uint64_t start = 0;
		uint64_t dur = 0;

		// Vector Aligned XOR
#if defined(__AVX512__)

		// sequential xor: 64 byte buffers
		OnProgress(std::string(glen + " using 64 byte buffers with sequential XOR "))
		buffer1.resize(64, (byte)0x7);
		buffer2.resize(64, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				for (size_t j = 0; j < buffer1.size(); ++j)
				{
					buffer2[j] ^= buffer1[j];
				}

				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));

		// simd256 xor
		OnProgress(std::string(glen + " using 64 byte buffers with AVX512 vectorized XOR "));
		buffer3.resize(64, (byte)0x7);
		buffer4.resize(64, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::XOR512(buffer3, 0, buffer4, 0);
				blkCtr += buffer3.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));

#elif defined(__AVX2__)
		// sequential xor: 32 byte buffers
		OnProgress(std::string(glen + " using 32 byte buffers with sequential XOR "));
		buffer1.resize(32, (byte)0x7);
		buffer2.resize(32, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				for (size_t j = 0; j < buffer1.size(); ++j)
				{
					buffer2[j] ^= buffer1[j];
				}
				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));

		// simd256 xor
		OnProgress(std::string(glen + " using 32 byte buffers with AVX2 vectorized XOR "));
		buffer3.resize(32, (byte)0x7);
		buffer4.resize(32, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::XOR256(buffer3, 0, buffer4, 0);
				blkCtr += buffer3.size();
			}
			blkCtr = 0;
		}
		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));

#elif defined(__AVX__)
		// sequential memset: 16 byte buffers
		OnProgress(std::string(glen + " using 16 byte buffers with sequential XOR "));
		buffer1.resize(16, (byte)0x7);
		buffer2.resize(16, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				for (size_t j = 0; j < buffer1.size(); ++j)
				{
					buffer2[j] ^= buffer1[j];
				}

				blkCtr += buffer1.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));

		// simd128 memset: 16 byte buffers
		OnProgress(std::string(glen + " using 16 byte buffers with AVX vectorized XOR "));
		buffer3.resize(16, (byte)0x7);
		buffer4.resize(16, (byte)0x11);
		start = TestUtils::GetTimeMs64();

		for (size_t i = 0; i < Loops; ++i)
		{
			while (blkCtr < Length)
			{
				MemUtils::XOR128(buffer3, 0, buffer4, 0);
				blkCtr += buffer3.size();
			}
			blkCtr = 0;
		}

		dur = TestUtils::GetTimeMs64() - start;
		PostPerfResult(dur, Length, std::string("XOR "));
#endif
	}

	void SimdSpeedTest::PostPerfResult(uint64_t Duration, uint64_t Length, const std::string &Message)
	{
		uint64_t rate = GetBytesPerSecond(Duration, Length);
		std::string mbps = TestUtils::ToString((rate / MB1));
		std::string secs = TestUtils::ToString((double)Duration / 1000.0);
		std::string resp = std::string(Message + TESTSIZE + " of data in " + secs + " seconds, avg. " + mbps + " MB per Second");

		OnProgress(resp);
	}

	//*** Helpers ***//

	uint64_t SimdSpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)DataSize;

		return (uint64_t)(sze / sec);
	}

	void SimdSpeedTest::Initialize()
	{
		try
		{
			Common::CpuDetect detect;
			m_hasAVX = detect.AVX();
			m_hasAVX2 = detect.AVX2();
			m_hasAVX512 = detect.AVX512F();
		}
		catch (...)
		{
			m_hasAVX = false;
			m_hasAVX2 = false;
			m_hasAVX512 = false;
		}
	}

	void SimdSpeedTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}