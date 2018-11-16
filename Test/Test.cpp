// HISTORY
//
// ### CEX 1.0.0.6 ###
// Current Release 1.0.0.6 (version A6)
// The SPHINCS+ asymmetric signature scheme
// The NTRU Prime asymmetric cipher
// Authenticated Threefish-256/512/1024 stream ciphers
// Authenticated ChaCha-256/512 stream ciphers
// The cSHAKE option (RSX) integrated into RHX/AHX
// Asymmetric ciphers updated to the NIST PQ Round 1 versions
//
// ### CEX 1.0.0.5 ###
// Current Release 1.0.0.5 (version A5)
// The ModuleLWE asymmetric cipher
// The SHAKE Key Derivation Function
// Addition of asymmetric cipher Encapsulate / Decapsulate api
// The library is now Misra C++ 2014 compliant
//
// ### CEX 1.0.0.4 ###
// 1.0.0.4, Full Release
// The full version will be Misra and SEI-CERT compliant, (eta. is mid December 2017)
// Added McEliece public key crypto system	-done
// Added Keccak1024 message digest	-done
// Added Poly1305 Mac and ChaCha/Poly1305 AEAD mode -(mode scheduled for 1.0.0.5)
// Reworked public classes/interfaces for POD data types in preparation for DLL interface -ongoing..
// Complete preformance optimization cycle; strategic memory allocation (stack or heap), and review class/function variables -ongoing..
// Complete security compliance cycle; all code reviewed and updated to MISRA/SEI-CERT security recommendations -ongoing..
//
// Release 1.0.0.3, June 30, 2017
// Added asymmetric cipher interfaces and framework
// Added RingLWE asymmetric cipher
// Added the Auto Collection seed Provider (ACP)
// Addition of the HCR prng
// Renaming of the drbgs to xCG format: BCG, DCG, and HCG; Block cipher Counter Generator, Digest and HMAC Counter Generators
// Overhaul of SecureRandom and prng classes
//
// Release 1.0.0.2, April 23, 2017
// Added and integrated a vectorized MemUtils class
// Added experimental AVX512 support
// Added UInt512 class
// Added MemUtils and SIMD tests
// Templated Chacha and Salsa
// Rewrites of Twofish and Serpent
// Headers are now documentation only (no inline accessors)
// Added override hint to virtual functions in headers
// Many small format changes and a couple of bug fixes
//
// Release 1.0.1.1, April 08, 2017
// Fixed a bug in CpuDetect (misreporting SIMD capabilities of some cpu's)
// Added preprocessor definitions for intrinsics throughout both projects
// Cleaned up the test project
// Changes to code required by Intel tool-chain
// Tested on Intel i3, i5, i7, and an AMD K9
// Tested on debug and release versions of ARM/x86/x64
// Tested on MSVC 2015 and 2017 ide
// Now supports arch:AVX2 (recommended), arch:AVX (minimum), or no intrinsics support, arch:IA32
// Many misc. internal todo's and rewrites completed
//
// Release 1.0.0.1
// Skein Tree			-done
// Rewrite SHA2			-done
// Rewrite Blake2		-done
// Keccak Tree			-done
// Scrypt				-done
// Code review			-done
// Help review			-done
//
// Release 0.14.2.1
// EAX/GCM/OCB			-done
// GMAC					-done
// Code review			-done
//
// Release 0.13
// HX kdf change		-done
// DCG/BCG/HCG Drbg		-done
// RDP/ECP/CJP provider -done
// Secure Key/mem		-done
// CipherStream rewrite	-done
// KeyGenerator rewrite	-dome	

// TRAJECTORY
//
// ### SCHEDULE FOR 1.0.0.7 RELEASE ###
// ## ETA is December 25, 2018 ##
// 
// Add SPHINCS+ signature scheme
// Add Dilithium signature scheme
//
//
// ### Planned Release 1.1.0.1 ###
//
// AVX512 integration		-started
// RingLWE					-added
// McEliece					-added
// ModuleLWE				-added
// NTRU						-added
// SPHINCS+					-added
// Dilithium				-
//
// ### Planned Release 1.2.0.1 ###
// STM - KEX
// Android / iOS / Linux compatibility
// DLL API
//
// ## Style Rules ##
// 
// namespace: Single capaitalized word, ex. Network::
// class name: Pascal case description, maximum of two words, ex. SymmetricKey()
// function name: Pascal case, maximum of two words, ex. Initialize()
// function parameters: Pascal case, maximum of two words, ex. Initialize(ISymmetricKey &Key)
// global variable: Camel Case, with the prefix 'g_', ex. g_globalState
// class variable: Camel Case, with the prefix 'm_', ex. m_classState
// function variable: a single word or 2 Camel case words in abbreviated form, ex. ctr, or, blkCtr
// global constant: All Caps, a total of three words with the 'CEX_' prefix, ex. CEX_GLOBAL_CONSTANT
// class constant: All Caps, a total of two words, ex. CLASS_CONSTANT
// function constant: Two capitalized and abbreviated 3 letter words with no underscore divider, ex. FNCCST

#include <fstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include "../CEX/CpuDetect.h"
#include "../Test/TestFiles.h"
#include "../Test/TestUtils.h"
#include "../Test/ACPTest.h"
#include "../Test/AeadTest.h"
#include "../Test/AesAvsTest.h"
#include "../Test/RijndaelTest.h"
#include "../Test/AsymmetricSpeedTest.h"
#include "../Test/BCGTest.h"
#include "../Test/Blake2Test.h"
#include "../Test/ChaChaTest.h"
#include "../Test/CipherModeTest.h"
#include "../Test/CipherSpeedTest.h"
#include "../Test/CipherStreamTest.h"
#include "../Test/CJPTest.h"
#include "../Test/CMACTest.h"
#include "../Test/ConsoleUtils.h"
#include "../Test/CSGTest.h"
#include "../Test/CSPTest.h"
#include "../Test/DigestSpeedTest.h"
#include "../Test/DigestStreamTest.h"
#include "../Test/ECPTest.h"
#include "../Test/GMACTest.h"
#include "../Test/KDF2Test.h"
#include "../Test/KeccakTest.h"
#include "../Test/KMACTest.h"
#include "../Test/HKDFTest.h"
#include "../Test/HMACTest.h"
#include "../Test/HCGTest.h"
#include "../Test/ITest.h"
#include "../Test/MacStreamTest.h"
#include "../Test/McElieceTest.h"
#include "../Test/MemUtilsTest.h"
#include "../Test/ModuleLWETest.h"
#include "../Test/NTRUTest.h"
#include "../Test/PaddingTest.h"
#include "../Test/ParallelModeTest.h"
#include "../Test/PBKDF2Test.h"
#include "../Test/Poly1305Test.h"
#include "../Test/RandomOutputTest.h"
#include "../Test/RDPTest.h"
#include "../Test/RingLWETest.h"
#include "../Test/SCRYPTTest.h"
#include "../Test/SecureStreamTest.h"
#include "../Test/SerpentTest.h"
#include "../Test/Sha2Test.h"
#include "../Test/SimdSpeedTest.h"
#include "../Test/SimdWrapperTest.h"
#include "../Test/SHAKETest.h"
#include "../Test/SkeinTest.h"
#include "../Test/SphincsTest.h"
#include "../Test/SymmetricKeyGeneratorTest.h"
#include "../Test/SymmetricKeyTest.h"
#include "../Test/ThreefishTest.h"
#include "../Test/UtilityTest.h"

using namespace Test;

std::string GetRandomString(size_t Length)
{
	std::string res;
	res = TestUtils::RandomReadableString(Length);

	return res;
}

void CpuCheck()
{
	Common::CpuDetect detect;
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

bool CanTest(std::string Message)
{
	ConsoleUtils::WriteLine(Message);
	std::string resp = GetResponse();

	const std::string CONFIRM = "y";
	const std::string CONFIRML = "Y";
	bool state = false;

	if (resp.find(CONFIRM) != std::string::npos || resp.find(CONFIRML) != std::string::npos)
	{
		state = true;
	}

	return state;
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
		sample = GetRandomString(120);
		ConsoleUtils::WriteLine(sample);
	}

	ConsoleUtils::WriteLine("");
}

void PrintTitle()
{
	ConsoleUtils::WriteLine("***********************************************");
	ConsoleUtils::WriteLine("* CEX++ Version 1.0.0.6: CEX Library in C++   *");
	ConsoleUtils::WriteLine("*                                             *");
	ConsoleUtils::WriteLine("* Release:   v1.0.0.6g (A6)                   *");
	ConsoleUtils::WriteLine("* License:   GPLv3                            *");
	ConsoleUtils::WriteLine("* Date:      November 16, 2018                *");
	ConsoleUtils::WriteLine("* Contact:   develop@vtdev.com                *");
	ConsoleUtils::WriteLine("***********************************************");
	ConsoleUtils::WriteLine("");
}

void CloseApp()
{
	PrintHeader("An error has occurred! Press any key to close..", "");
	GetResponse();
	exit(0);
}

void RunTest(ITest* Test)
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
	catch (TestException &ex)
	{
		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("*** ERROR CONDITION ***");


		if (ex.Origin().size() != 0)
		{
			ConsoleUtils::WriteLine(std::string("Origin: ") + ex.Origin());
			ConsoleUtils::WriteLine(std::string("Message: ") + ex.Message());
		}
		else if (ex.Message().size() != 0)
		{
			ConsoleUtils::WriteLine(std::string("Message: ") + ex.Message());
		}

		ConsoleUtils::WriteLine(std::string("Time: ") + GetTime());
		ConsoleUtils::WriteLine("");

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");

		std::string resp;
		std::getline(std::cin, resp);

		if (CanTest(resp))
		{
			CloseApp();
		}
	}
}

int main()
{
	bool hasAes;
	bool hasAvx;
	bool hasAvx2;
	bool isx86emu;
	bool is64;

	ConsoleUtils::SizeConsole();
	PrintTitle();

#if !defined(_OPENMP)
	PrintHeader("Warning! This library requires OpenMP support, the test can not coninue!");
	PrintHeader("An error has occurred! Press any key to close..", "");
	GetResponse();

	return 0;
#endif

	std::string data("");

	try
	{
		TestUtils::Read(TestFiles::AESAVS::AESAVSKEY128, data);
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
		GetResponse();

		return 0;
	}

	hasAes = false;
	hasAvx = false;
	hasAvx2 = false;
	isx86emu = false;
	is64 = false;

	try
	{
		Common::CpuDetect detect;

		hasAes = detect.AESNI();
		hasAvx = detect.AVX();
		hasAvx2 = detect.AVX2();
		isx86emu = detect.IsX86Emulation();
		is64 = detect.IsX64();
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! This platform does not support cpudetect!", "");
		GetResponse();

		return 0;
	}

#if (!defined(_M_X64) && !defined(__x86_64__) && !defined(_DEBUG))
	if (is64 || isx86emu)
	{
		PrintHeader("Warning! Compiling x86/Release on a 64bit system will cause memory alignment errors.", "");
		PrintHeader("To test x86/Release, compile on a true x86 system, or run in x86/Debug mode.", "");
		PrintHeader("Tests aborted! Press any key to close..", "");
		GetResponse();

		return 0;
	}
#endif

	if (hasAes)
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

		if (CanTest("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: "))
		{
			PrintHeader("TESTING SYMMETRIC BLOCK CIPHERS");

			if (hasAes)
			{
				PrintHeader("Testing the AES-NI implementation (AHX)");
				RunTest(new AesAvsTest(true));
			}

			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesAvsTest());

			if (hasAes)
			{
				PrintHeader("Testing the AES-NI implementation (AHX)");
				RunTest(new RijndaelTest(true));
			}

			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new RijndaelTest());
			PrintHeader("Testing the Serpent software implementation (SHX)");
			RunTest(new SerpentTest());
			PrintHeader("TESTING SYMMETRIC CIPHER MODES");
			RunTest(new CipherModeTest());
			PrintHeader("TESTING SYMMETRIC CIPHER AEAD MODES");
			RunTest(new AeadTest());
			PrintHeader("TESTING PARALLEL CIPHER MODES");
			RunTest(new ParallelModeTest());
			PrintHeader("TESTING CIPHER PADDING MODES");
			RunTest(new PaddingTest());
			PrintHeader("TESTING SYMMETRIC STREAM CIPHERS");
			RunTest(new ChaChaTest());
			RunTest(new ThreefishTest());
			PrintHeader("TESTING CRYPTOGRAPHIC STREAM PROCESSORS");
			RunTest(new CipherStreamTest());
			RunTest(new DigestStreamTest());
			RunTest(new MacStreamTest());
			PrintHeader("TESTING CRYPTOGRAPHIC HASH GENERATORS");
			RunTest(new Blake2Test());
			RunTest(new KeccakTest());
			RunTest(new SHA2Test());
			RunTest(new SkeinTest());
			PrintHeader("TESTING MESSAGE AUTHENTICATION CODE GENERATORS");
			RunTest(new CMACTest());
			RunTest(new GMACTest());
			RunTest(new HMACTest());
			RunTest(new KMACTest());
			RunTest(new Poly1305Test());
			PrintHeader("TESTING PSEUDO RANDOM NUMBER GENERATORS");
			RunTest(new ACPTest());
			RunTest(new CJPTest());
			RunTest(new CSPTest());
			RunTest(new ECPTest());
			RunTest(new RDPTest());
			PrintHeader("TESTING KEY DERIVATION FUNCTIONS");
			RunTest(new HKDFTest());
			RunTest(new KDF2Test());
			RunTest(new PBKDF2Test());
			RunTest(new SCRYPTTest());
			RunTest(new SHAKETest());
			PrintHeader("TESTING DETERMINISTIC RANDOM BYTE GENERATORS");
			RunTest(new BCGTest());
			RunTest(new CSGTest());
			RunTest(new HCGTest());
			PrintHeader("TESTING KEY GENERATOR AND SECURE KEYS");
			RunTest(new SymmetricKeyGeneratorTest());
			RunTest(new SecureStreamTest());
			RunTest(new SymmetricKeyTest());
			PrintHeader("TESTING VECTORIZED MEMORY FUNCTIONS");
			RunTest(new MemUtilsTest());
			RunTest(new SimdWrapperTest());
			PrintHeader("TESTING UTILITY CLASS FUNCTIONS");
			RunTest(new UtilityTest());
			PrintHeader("TESTING ASYMMETRIC CIPHERS");
			RunTest(new McElieceTest());
			RunTest(new ModuleLWETest());
			RunTest(new NTRUTest());
			RunTest(new RingLWETest());
			PrintHeader("TESTING ASYMMETRIC SIGNATURE SCHEMES");
			RunTest(new SphincsTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Diagnostic tests were Cancelled..");
		}

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("");

#if defined(__AVX__)
		if (CanTest("Press 'Y' then Enter to run SIMD Memory operations Speed Tests, any other key to cancel: "))
		{
			RunTest(new SimdSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("SIMD Memory Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");
#endif

		if (CanTest("Press 'Y' then Enter to run Symmetric Cipher Speed Tests, any other key to cancel: "))
		{
			RunTest(new CipherSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Cipher Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		if (CanTest("Press 'Y' then Enter to run Message Digest Speed Tests, any other key to cancel: "))
		{
			RunTest(new DigestSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Digest Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		if (CanTest("Press 'Y' then Enter to run Asymmetric Cipher Speed Tests, any other key to cancel: "))
		{
			RunTest(new AsymmetricSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Asymmetric Cipher Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		PrintHeader("Completed! Press any key to close..", "");
		GetResponse();

		return 0;
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! Press any key to close..", "");
		GetResponse();

		return 0;
	}
}
