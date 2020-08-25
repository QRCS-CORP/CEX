// Development Map
// 1.0.0.8f
// re-work asymmetric keys -done
// change key naming nonce to iv -done
// complete documentation review -done
// complete code review -done
// changes to RCS/HBA key schedule -done
// network tests -
// aes KATS to NIST file format -done

// 1.0.0.9a
// internal migration to secure vectors
// 
// 1.0.0.9b
// linux, gcc
// 
// 1.0.0.9c
// upgrade asymmetric ciphers to round 3 versions
// 
// 1.0.0.9d
// Post quantum TLS

#include <iostream>
#include <stdio.h>
#include <string>
#include "../CEX/CpuDetect.h"
#include "../Test/TestFiles.h"
#include "../Test/TestUtils.h"
#include "../Test/ACPTest.h"
#include "../Test/AeadTest.h"
#include "../Test/AesAvsTest.h"
#include "../Test/AsymmetricKeyTest.h"
#include "../Test/AsymmetricSpeedTest.h"
#include "../Test/BCGTest.h"
#include "../Test/BCRTest.h"
#include "../Test/Blake2Test.h"
#include "../Test/CSXTest.h"
#include "../Test/CipherModeTest.h"
#include "../Test/CipherSpeedTest.h"
#include "../Test/CipherStreamTest.h"
#include "../Test/CJPTest.h"
#include "../Test/CMACTest.h"
#include "../Test/ConsoleUtils.h"
#include "../Test/CSGTest.h"
#include "../Test/CSPTest.h"
#include "../Test/CSRTest.h"
#include "../Test/DigestSpeedTest.h"
#include "../Test/DigestStreamTest.h"
#include "../Test/DilithiumTest.h"
#include "../Test/DUKPTTest.h"
#include "../Test/ECPTest.h"
#include "../Test/GMACTest.h"
#include "../Test/HCRTest.h"
#include "../Test/KDF2Test.h"
#include "../Test/SHA3Test.h"
#include "../Test/KMACTest.h"
#include "../Test/HKDFTest.h"
#include "../Test/HKDSTest.h"
#include "../Test/HMACTest.h"
#include "../Test/HCGTest.h"
#include "../Test/ITest.h"
#include "../Test/MacStreamTest.h"
#include "../Test/McElieceTest.h"
#include "../Test/MemUtilsTest.h"
#include "../Test/KyberTest.h"
#include "../Test/NewHopeTest.h"
#include "../Test/NTRUPrimeTest.h"
#include "../Test/PaddingTest.h"
#include "../Test/ParallelModeTest.h"
#include "../Test/PBKDF2Test.h"
#include "../Test/Poly1305Test.h"
#include "../Test/RainbowTest.h"
#include "../Test/RandomOutputTest.h"
#include "../Test/RCSTest.h"
#include "../Test/RDPTest.h"
#include "../Test/RijndaelTest.h"
#include "../Test/SCBKDFTest.h"
#include "../Test/RWSTest.h"
#include "../Test/SecureStreamTest.h"
#include "../Test/SerpentTest.h"
#include "../Test/Sha2Test.h"
#include "../Test/SimdSpeedTest.h"
#include "../Test/SimdWrapperTest.h"
#include "../Test/SHAKETest.h"
#include "../Test/SkeinTest.h"
#include "../Test/SphincsPlusTest.h"
#include "../Test/SymmetricKeyGeneratorTest.h"
#include "../Test/SymmetricKeyTest.h"
#include "../Test/ThreefishTest.h"
#include "../Test/UtilityTest.h"
#include "../Test/XMSSTest.h"

using namespace Test;

void CpuCheck()
{
	CpuDetect detect;

	ConsoleUtils::WriteLine("L1 cache size: " + std::to_string(detect.L1CacheSize()));
	ConsoleUtils::WriteLine("Total L1 cache size: " + std::to_string(detect.L1CacheTotal()));
	ConsoleUtils::WriteLine("L1 cache line size: " + std::to_string(detect.L1CacheLineSize()));
	ConsoleUtils::WriteLine("L2 cache size: " + std::to_string(detect.L2CacheSize()));
	ConsoleUtils::WriteLine("Physical cores: " + std::to_string(detect.PhysicalCores()));
	ConsoleUtils::WriteLine("Virtual cores: " + std::to_string(detect.VirtualCores()));
	ConsoleUtils::WriteLine("HyperThreading: " + std::to_string(detect.HyperThread()));
	ConsoleUtils::WriteLine("AES-NI: " + std::to_string(detect.AESNI()));
	ConsoleUtils::WriteLine("AVX: " + std::to_string(detect.AVX()));
	ConsoleUtils::WriteLine("AVX2: " + std::to_string(detect.AVX2()));
	ConsoleUtils::WriteLine("CMUL: " + std::to_string(detect.CMUL()));
	ConsoleUtils::WriteLine("RDRAND: " + std::to_string(detect.RDRAND()));
	ConsoleUtils::WriteLine("RDTSCP: " + std::to_string(detect.RDTSCP()));
	ConsoleUtils::WriteLine("SHA: " + std::to_string(detect.SHA()));
	ConsoleUtils::WriteLine("SSE2: " + std::to_string(detect.SSE2()));
	ConsoleUtils::WriteLine("SSE3: " + std::to_string(detect.SSE3()));
	ConsoleUtils::WriteLine("SSSE3: " + std::to_string(detect.SSSE3()));
	ConsoleUtils::WriteLine("SSE41: " + std::to_string(detect.SSE41()));
	ConsoleUtils::WriteLine("SSE42: " + std::to_string(detect.SSE42()));
	ConsoleUtils::WriteLine("XOP: " + std::to_string(detect.XOP()));
	ConsoleUtils::WriteLine("");
}

std::string GetResponse()
{
	std::string resp = "";

	try
	{
		std::getline(std::cin, resp);
	}
	catch (std::exception&)
	{
	}

	return resp;
}

std::string GetTime()
{
	time_t res = time(nullptr);
	char str[26];
	ctime_s(str, sizeof(str), &res);

	return std::string(str);
}

void PrintHeader(std::string Data, std::string Decoration = "***")
{
	ConsoleUtils::WriteLine(Decoration + Data + Decoration);
}

void PrintRandom(size_t Lines)
{
	std::string sample;

	for (size_t i = 0; i < Lines; ++i)
	{
		sample = TestUtils::GetRandomString(120);
		ConsoleUtils::WriteLine(sample);
	}

	ConsoleUtils::WriteLine("");
}

void PrintTitle()
{
	ConsoleUtils::WriteLine("************************************************");
	ConsoleUtils::WriteLine("* CEX++ Version 1.0.0.8: CEX Library in C++    *");
	ConsoleUtils::WriteLine("*                                              *");
	ConsoleUtils::WriteLine("* Release:   v1.0.0.8g (A8)                    *");
	ConsoleUtils::WriteLine("* License:   GPLv3                             *");
	ConsoleUtils::WriteLine("* Date:      August 21, 2020                   *");
	ConsoleUtils::WriteLine("* Contact:   develop@vtdev.com                 *");
	ConsoleUtils::WriteLine("************************************************");
	ConsoleUtils::WriteLine("");
}

bool TestConfirm(std::string Message)
{
	const std::string CONFIRM = "y";
	const std::string CONFIRML = "Y";
	std::string resp;
	bool state;

	ConsoleUtils::WriteLine(Message);

	state = false;
	resp = GetResponse();

	if (resp.find(CONFIRM) != std::string::npos || resp.find(CONFIRML) != std::string::npos)
	{
		state = true;
	}

	return state;
}

void Terminate()
{
	std::string resp;

	PrintHeader("An error has occurred! Press any key to close..", "");
	TestUtils::WaitForInput();
	exit(0);
}

void TestRun(ITest* Test)
{
	try
	{
		TestEventHandler handler;
		Test->Progress() += &handler;
		ConsoleUtils::WriteLine(Test->Description());
		ConsoleUtils::WriteLine(Test->Run());
		Test->Progress() -= &handler;
		ConsoleUtils::WriteLine("");

		delete Test;
	}
	catch (TestException const &ex)
	{
		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("*** ERROR CONDITION ***");
		ConsoleUtils::WriteLine(std::string("Class: ") + ex.Location());
		ConsoleUtils::WriteLine(std::string("Function: ") + ex.Function());
		ConsoleUtils::WriteLine(std::string("Origin: ") + ex.Origin());
		ConsoleUtils::WriteLine(std::string("Message: ") + ex.Message());
		ConsoleUtils::WriteLine(std::string("Time: ") + GetTime());
		ConsoleUtils::WriteLine("");

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");

		std::string resp;

		if (!TestConfirm(resp))
		{
			Terminate();
		}
	}
}

int main()
{
	bool hasAesni;
	bool hasAvx;
	bool hasAvx2;
	bool isx86emu;
	bool is64bit;

	ConsoleUtils::SizeConsole();
	PrintTitle();

#if !defined(_OPENMP)
	PrintHeader("Warning! This library uses OpenMP which was not detected, performance may be sub-optimal!");
	PrintHeader("");
#endif

	std::string data("");

	try
	{
		TestUtils::Read(TestFiles::AESAVS::AESCBC128_VARKEY, data);
	}
	catch (std::exception&) 
	{
		data = "";
	}

	if (data.size() == 0)
	{
		PrintHeader("Warning! Could not find the cipher test vector KAT files!");
		PrintHeader("The Win/Test/Vectors folder must be in the executables path.", "");
		PrintHeader("An error has occurred! Press any key to close..", "");
		TestUtils::WaitForInput();

		return 0;
	}
	else
	{
		data.clear();
	}

	hasAesni = false;
	hasAvx = false;
	hasAvx2 = false;
	isx86emu = false;
	is64bit = false;

	try
	{
		CpuDetect detect;

		hasAesni = detect.AESNI();
		hasAvx = detect.AVX();
		hasAvx2 = detect.AVX2();
		isx86emu = detect.IsX86Emulation();
		is64bit = detect.IsX64();
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! This platform does not support cpudetect!", "");
		TestUtils::WaitForInput();

		return 0;
	}

#if (!defined(_M_X64) && !defined(__x86_64__) && !defined(_DEBUG))
	if (is64bit || isx86emu)
	{
		PrintHeader("Warning! Compiling x86/Release on a 64bit system will cause memory alignment errors.", "");
		PrintHeader("To test x86/Release, compile on a true x86 system, or run in x86/Debug mode.", "");
		PrintHeader("Tests aborted! Press any key to close..", "");
		TestUtils::WaitForInput();

		return 0;
	}
#endif

	if (hasAesni)
	{
		PrintHeader("AES-NI intrinsics support has been detected on this system.");
	}
	else
	{
		PrintHeader("AES-NI intrinsics support was not detected on this system.");
	}
	PrintHeader("", "");

	if (hasAvx2)
	{
#if !defined(__AVX2__)
		PrintHeader("Warning! AVX2 support was detected! Set the enhanced instruction set to arch:AVX2 for best performance.");
#else
		PrintHeader("AVX2 intrinsics support has been enabled.");
#endif
	}
	else if (hasAvx)
	{
#if defined(__AVX2__)
		PrintHeader("AVX2 is not supported on this system! AVX intrinsics support is available, set enable enhanced instruction set to arch:AVX");
#elif !defined(__AVX__)
		PrintHeader("AVX intrinsics support has been detected, set enhanced instruction set to arch:AVX for best performance.");
#else
		PrintHeader("AVX intrinsics support has been enabled.");
#endif
	}
	else
	{
		PrintHeader("The minimum SIMD intrinsics support (AVX) was not detected, intrinsics have been disabled!");
	}
	PrintHeader("", "");

	try
	{
#if defined (_DEBUG)
		PrintHeader("Warning! Compile as Release with correct platform (x86/x64) for accurate timings");
		PrintHeader("", "");
#endif

		if (TestConfirm("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: "))
		{
			PrintHeader("TESTING SYMMETRIC BLOCK CIPHERS");

#if defined(__AVX__)
			if (hasAesni)
			{
				PrintHeader("Testing the AES-NI implementation (AES-NI)");
				TestRun(new AesAvsTest(true));
			}
#endif

			PrintHeader("Testing the AES software implementation (AES)");
			TestRun(new AesAvsTest(false));

#if defined(__AVX__)
			if (hasAesni)
			{
				PrintHeader("Testing the AES-NI implementation (AES-NI)");
				TestRun(new RijndaelTest(true));
			}
#endif

			PrintHeader("Testing the AES software implementation (RHX)");
			TestRun(new RijndaelTest(false));
			PrintHeader("Testing the Serpent software implementation (SHX)");
			TestRun(new SerpentTest());
			PrintHeader("TESTING SYMMETRIC CIPHER MODES");
			TestRun(new CipherModeTest());
			PrintHeader("TESTING SYMMETRIC CIPHER AEAD MODES");
			TestRun(new AeadTest());
			PrintHeader("TESTING PARALLEL CIPHER MODES");
			TestRun(new ParallelModeTest());
			PrintHeader("TESTING CIPHER PADDING MODES");
			TestRun(new PaddingTest());
			PrintHeader("TESTING SYMMETRIC STREAM CIPHERS");
			TestRun(new CSXTest());
			TestRun(new RCSTest());
			TestRun(new RWSTest());
			TestRun(new ThreefishTest());
			PrintHeader("TESTING CRYPTOGRAPHIC STREAM PROCESSORS");
			TestRun(new CipherStreamTest());
			TestRun(new DigestStreamTest());
			TestRun(new MacStreamTest());
			PrintHeader("TESTING CRYPTOGRAPHIC HASH GENERATORS");
			TestRun(new Blake2Test());
			TestRun(new SHA3Test());
			TestRun(new SHA2Test());
			TestRun(new SkeinTest());
			PrintHeader("TESTING MESSAGE AUTHENTICATION CODE GENERATORS");
			TestRun(new CMACTest());
			TestRun(new GMACTest());
			TestRun(new HMACTest());
			TestRun(new KMACTest());
			TestRun(new Poly1305Test());
			PrintHeader("TESTING RANDOM ENTROPY PROVIDERS");
			TestRun(new ACPTest());
#if defined(__AVX__)
			TestRun(new CJPTest());
#endif
			TestRun(new CSPTest());
			TestRun(new ECPTest());
#if defined(__AVX__)
			TestRun(new RDPTest());
#endif
			PrintHeader("TESTING PSEUDO RANDOM NUMBER GENERATORS");
			TestRun(new BCRTest());
			TestRun(new CSRTest());
			TestRun(new HCRTest());
			PrintHeader("TESTING KEY DERIVATION FUNCTIONS");
			TestRun(new HKDFTest());
			TestRun(new KDF2Test());
			TestRun(new PBKDF2Test());
			TestRun(new SCBKDFTest());
			TestRun(new SHAKETest());
			PrintHeader("TESTING KEY MANAGEMENT SYSTEMS");
			TestRun(new DUKPTTest());
			TestRun(new HKDSTest());
			PrintHeader("TESTING DETERMINISTIC RANDOM BYTE GENERATORS");
			TestRun(new BCGTest());
			TestRun(new CSGTest());
			TestRun(new HCGTest());
			PrintHeader("TESTING KEY GENERATOR AND SECURE KEYS");
			TestRun(new AsymmetricKeyTest());
			TestRun(new SymmetricKeyGeneratorTest());
			TestRun(new SecureStreamTest());
			TestRun(new SymmetricKeyTest());
			PrintHeader("TESTING VECTORIZED MEMORY FUNCTIONS");
			TestRun(new MemUtilsTest());
			TestRun(new SimdWrapperTest());
			PrintHeader("TESTING UTILITY CLASS FUNCTIONS");
			TestRun(new UtilityTest());
			PrintHeader("TESTING ASYMMETRIC CIPHERS");
			TestRun(new KyberTest());
			TestRun(new McElieceTest());
			TestRun(new NewHopeTest());
			TestRun(new NTRUPrimeTest());
			PrintHeader("TESTING ASYMMETRIC SIGNATURE SCHEMES");
			TestRun(new DilithiumTest());
			TestRun(new RainbowTest());
			TestRun(new SphincsPlusTest());
			TestRun(new XMSSTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Diagnostic tests were Cancelled..");
		}

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("");

#if defined(__AVX__)
		if (TestConfirm("Press 'Y' then Enter to run SIMD Memory operations Speed Tests, any other key to cancel: "))
		{
			TestRun(new SimdSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("SIMD Memory Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");
#endif

		if (TestConfirm("Press 'Y' then Enter to run Symmetric Cipher Speed Tests, any other key to cancel: "))
		{
			TestRun(new CipherSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Cipher Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		if (TestConfirm("Press 'Y' then Enter to run Message Digest Speed Tests, any other key to cancel: "))
		{
			TestRun(new DigestSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Digest Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		if (TestConfirm("Press 'Y' then Enter to run Asymmetric Cipher Speed Tests, any other key to cancel: "))
		{
			TestRun(new AsymmetricSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Asymmetric Cipher Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		PrintHeader("Completed! Press any key to close..", "");
		TestUtils::WaitForInput();

		return 0;
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! Press any key to close..", "");
		TestUtils::WaitForInput();

		return 0;
	}
}





















































// Misc Notes
//
// DTM Model
// 
//					Certification Authority
//				/							\
//			Authentication Agent			AA(...)
//			/	|		|		\			/\
//	Protected Domain	PD		PD			PD(...)
//					PQSECDNS
//		/		|		|			\		/||\
//	Requesting Host		RH			RH	    RH(...)

// TODO 1.8
// What can and should be serialized? (digests, kdfs, ciphers..)
// Correct function states, all local variables should be contained in the state class (excepting instances)
// Timing neutral sweep, check as much as you can
// Add Power8/9 and ARM support for RHX, RCS
// Linux, Apple support
// test on more CPUs
// ...
