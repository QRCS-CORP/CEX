// HISTORY
//
// ### CEX 1.0.0.4 ###
// 1.0.0.4, Preliminary Release
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
// ### SCHEDULE FOR 1.0.0.6 RELEASE ###
// ## ETA is March 31, 2018 ##
// 
// Add NTRU Prime
// Add cSHAKE DRBG
// Add asymmetric IAuthenticator CCA interface
// Add KMAC
// Rewrite ACP/ECP
//
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
//
//
// ### Planned Release 1.1.0.1 ###
//
// AVX512 integration		-started
// RingLWE					-added
// McEliece					-added
// ModuleLWE				-added
// NTRU Prime
// SPHINCS+
// Picnic
//
// ### Planned Release 1.2.0.1 ###
// TLS
// STM - KEX
// Android / iOS / Linux compatibility
// DLL API

#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "../CEX/CpuDetect.h"
#include "../Test/TestFiles.h"
#include "../Test/TestUtils.h"
#include "../Test/AEADTest.h"
#include "../Test/AesAvsTest.h"
#include "../Test/AesFipsTest.h"
#include "../Test/AsymmetricSpeedTest.h"
#include "../Test/Blake2Test.h"
#include "../Test/ChaChaTest.h"
#include "../Test/CipherModeTest.h"
#include "../Test/CipherSpeedTest.h"
#include "../Test/CipherStreamTest.h"
#include "../Test/CMACTest.h"
#include "../Test/ConsoleUtils.h"
#include "../Test/CMGTest.h"
#include "../Test/DCGTest.h"
#include "../Test/DigestSpeedTest.h"
#include "../Test/DigestStreamTest.h"
#include "../Test/GMACTest.h"
#include "../Test/KDF2Test.h"
#include "../Test/KeccakTest.h"
#include "../Test/HKDFTest.h"
#include "../Test/HMACTest.h"
#include "../Test/HMGTest.h"
#include "../Test/HXCipherTest.h"
#include "../Test/ITest.h"
#include "../Test/MacStreamTest.h"
#include "../Test/McElieceTest.h"
#include "../Test/MemUtilsTest.h"
#include "../Test/ModuleLWETest.h"
#include "../Test/PaddingTest.h"
#include "../Test/ParallelModeTest.h"
#include "../Test/PBKDF2Test.h"
#include "../Test/Poly1305Test.h"
#include "../Test/PrngTest.h"
#include "../Test/RandomOutputTest.h"
#include "../Test/RijndaelTest.h"
#include "../Test/RingLWETest.h"
#include "../Test/SalsaTest.h"
#include "../Test/SCRYPTTest.h"
#include "../Test/SecureStreamTest.h"
#include "../Test/SerpentTest.h"
#include "../Test/Sha2Test.h"
#include "../Test/SimdSpeedTest.h"
#include "../Test/SimdWrapperTest.h"
#include "../Test/SHAKETest.h"
#include "../Test/SkeinTest.h"
#include "../Test/SymmetricKeyGeneratorTest.h"
#include "../Test/SymmetricKeyTest.h"
#include "../Test/TwofishTest.h"
#include "../Test/UtilityTest.h"

using namespace Test;

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

bool CanTest(std::string Message)
{
	ConsoleUtils::WriteLine(Message);
	std::string resp = GetResponse();
	std::transform(resp.begin(), resp.end(), resp.begin(), ::toupper);

	const std::string CONFIRM = "Y";
	bool state = false;

	if (resp.find(CONFIRM) != std::string::npos)
	{
		state = true;
	}

	return state;
}

void PrintHeader(std::string Data, std::string Decoration = "***")
{
	ConsoleUtils::WriteLine(Decoration + Data + Decoration);
}

void PrintTitle()
{
	ConsoleUtils::WriteLine("**********************************************");
	ConsoleUtils::WriteLine("* CEX++ Version 1.0.0.5: CEX Library in C++  *");
	ConsoleUtils::WriteLine("*                                            *");
	ConsoleUtils::WriteLine("* Release:   v1.0.0.5 (A5)                   *");
	ConsoleUtils::WriteLine("* License:   GPLv3                           *");
	ConsoleUtils::WriteLine("* Date:      February 19, 2018               *");
	ConsoleUtils::WriteLine("* Contact:   develop@vtdev.com               *");
	ConsoleUtils::WriteLine("**********************************************");
	ConsoleUtils::WriteLine("");
}

void CloseApp()
{
	PrintHeader("An error has occurred! Press any key to close..", "");
	GetResponse();
	exit(0);
}

void RunTest(Test::ITest* Test)
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
		ConsoleUtils::WriteLine("An error has occured!");

		if (ex.Message().size() != 0)
		{
			ConsoleUtils::WriteLine(ex.Message());
		}

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");

		std::string resp;
		std::getline(std::cin, resp);
		std::transform(resp.begin(), resp.end(), resp.begin(), ::toupper);

		const std::string CONTINUE = "Y";
		if (resp.find(CONTINUE) == std::string::npos)
		{
			CloseApp();
		}
	}
}

int main()
{
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

	bool hasAes = false;
	bool hasAvs = false;
	bool hasAvs2 = false;
	bool isx86emu = false;
	bool is64 = false;

	try
	{
		Common::CpuDetect detect;

		hasAes = detect.AESNI();
		hasAvs = detect.AVX();
		hasAvs2 = detect.AVX2();
		isx86emu = detect.IsX86Emulation();
		is64 = detect.IsX64();
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! This platform does not support cpudetect!", "");
		GetResponse();

		return 0;
	}

#if ((!defined(_M_X64)) && (!defined(__x86_64__))) && ((defined(__AVX__) || defined(__AVX2__)) && (!defined(_DEBUG)))
	if (is64 || isx86emu)
	{
		PrintHeader("Warning! Compiling x86/Release on a 64bit system using AVX/AVX2 will cause memory alignment errors.", "");
		PrintHeader("To test x86/Release, compile on a true x86 system, or disable enhanced instruction sets (arch:IA32), or run in x86/Debug mode.", "");
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

	if (hasAvs2)
	{
#if !defined(__AVX2__)
		PrintHeader("Warning! AVX2 support was detected! Set the enhanced instruction set to arch:AVX2 for best performance.");
#else
		PrintHeader("AVX2 intrinsics support has been enabled.");
#endif
	}
	else if (hasAvs)
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
				RunTest(new AesFipsTest(true));
			}

			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesFipsTest());
			RunTest(new RijndaelTest());
			RunTest(new SerpentTest());
			RunTest(new TwofishTest());
			PrintHeader("TESTING HX EXTENDED CIPHERS");
			RunTest(new HXCipherTest());
			PrintHeader("TESTING SYMMETRIC CIPHER MODES");
			RunTest(new CipherModeTest());
			PrintHeader("TESTING SYMMETRIC CIPHER AEAD MODES");
			RunTest(new AEADTest());
			PrintHeader("TESTING PARALLEL CIPHER MODES");
			RunTest(new ParallelModeTest());
			PrintHeader("TESTING CIPHER PADDING MODES");
			RunTest(new PaddingTest());
			PrintHeader("TESTING SYMMETRIC STREAM CIPHERS");
			RunTest(new ChaChaTest());
			RunTest(new SalsaTest());
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
			RunTest(new Poly1305Test());
			PrintHeader("TESTING PSEUDO RANDOM NUMBER GENERATORS");
			RunTest(new PrngTest());
			PrintHeader("TESTING KEY DERIVATION FUNCTIONS");
			RunTest(new HKDFTest());
			RunTest(new KDF2Test());
			RunTest(new PBKDF2Test());
			RunTest(new SCRYPTTest());
			RunTest(new SHAKETest());
			PrintHeader("TESTING DETERMINISTIC RANDOM BYTE GENERATORS");
			RunTest(new CMGTest());
			RunTest(new DCGTest());
			RunTest(new HMGTest());
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
			RunTest(new RingLWETest());
			RunTest(new McElieceTest());
			RunTest(new ModuleLWETest());
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
