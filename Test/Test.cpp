// HISTORY
//
// ### CEX 1.0.0.4 ###
// 1.0.0.4, Preliminary Release
// The full version will be Misra and SEI-CERT compliant, (eta. is mid November 2017)
// Added McEliece public key crypto system	-done
// Added Keccak1024 message digest	-done
// Added Poly1305 Mac and ChaCha/Poly1305 AEAD mode -todo
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
// ### SCHEDULE FOR 1.0.0.4 RELEASE ###
// ## ETA is November 14, 2017 ##
// Complete performance optimizations on all classes
// Complete security audit and rewrite
// Add Poly1305 MAC
// Make authenticated KEX changes to RingLWE
//
// ### JSF/MISRA/SEI-CERT Check LIST ###
// ## Local Changes ##
// ensure that operations on signed integers do not result in overflow -done
// ensure that division and remainder operations do not result in divide-by-zero errors -done
// do not shift an expression by a negative number of bits or by greater than or equal to the number of bits that exist in the operand -done
// make all (public) functions const correct -ongoing
// reduce the number of class level variables (consider performance vs safety) -1.0.0.5
// make as many class functions static as possible -1.0.0.5
// reduce the number of function parameters whenever possible -done
// replace macros with inline functions -done
// mark single parameter constructors as explicit -done
// replace all instances of pointer math -done
// replave all C (*) pointers with std::unique_ptr, including public constructors and test framework -ongoing
// replace all C style casts with C++ equivalents, ex. static_cast<>() -done
// compound integer operations should be expressed within parenthesis to statically define operation flow, ex.  a = (b * (c << 3)) -done
// verify that all class scope variables are destroyed/reset in the destructor -done
// make the Destroy() functions private (confusing, and no need for them to be public) -done; kept in keys and streams, moved to finalizer for everything else
// delete unused default/copy/move constructors from all structs and classes -done
// replace all macros with inline/templated functions -done
// on pointer comparisons to zero, replace '0' with nullptr (ex. y* != nullptr) -done
// review and rewrite the entire test framework for compliance -todo in 1.0.0.5
//
// ## Global Changes ##
// all hex codes should be expressed in capitals, ex. 0xFF -done
// enum members should all be byte sized and sequential, i.e. 1,2,3.. (promote jump lists) -done
// reduce the number of global includes, and replace all C headers with C++ versions -done
// remove unused macros and defines in CEXCommon.h -done
// prefer static/extern const integers to #define -done
// add GNU header to each (major) header file -done
// internally, move from C style pointers (*) to std::unique_ptr -done
// all input pointers and types are tested and throw in constructor -done
// move exceptions to constructor initialization list from constructor body -done
// make sure every exception is documented -done
// use assert in busy functions, but use exceptions in constructor and initialize -done
// check every constructor initialize list for order and completeness -done
// all case statements must have braces and default -done
// make access to classes as restrictive as possibe (move/copy ctors), and make it so that incorrect usage is impossible or throws -done
// no increment/decrement operators inside a statement or indice, i.e. arr1[i++] or, while(--i >= 0) -done
// document all publicly visible functions and constants -done
// enum member numerical value requires static_cast, remove all C style casting -done
// new class order; constructors proceed properties -done
// convert all C-style static arrays to std::array -done
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
// ## Upgrades ##
// add GCM authentication mode to RingLWE -done
// add Padding property (and mechanism) -moved to KEM spec.
// revise parallel options, replace Parallel parameter with cpu count (CpuCores), and make core count assignable -moved to api eval. 1.0.0.5
//
//
// ### Optimization Cycle 1: Sept 26, 2017 ###
// Performance of various algorithms pre/post memory and code optimizations
// Best set of five: Win10/i7-6700/VS2015
//
// ## Stage 1 (baseline) ##
// #asymmetric ciphers in operations per second, best of 4
// RingLWE: Gen 14285/17345, Enc 10000/12547, Dec 33333
// McEliece: Gen 12, Enc 7692, Dec 4000
//
// #symmetric ciphers in MB per second
// AHX: ECB 11299, CTR 426/7633, ICM 172/8064, CBC 715/9803, CFB 352/2277, OFB 307, EAX 205/616, OCB 107/1013, GCM 311/1060
// SHX: ECB 2418
// THX: ECB 1002
// ChaCha: 6097
// Salsa: 6622
//
// #message digests in MB per second
// Blake2: 512- 677/1831, 256- 376/1636
// Keccak: 1024- 79/314, 512- 155/400, 256- 294/1152
// SHA2: 512- 335/1312, 256- 193/788
// Skein: 1024- 350/1412, 512- 236/1204, 256- 221/929
//
// #memory in MB per second
// Memory: LB Clear 6993, Clear 10309, LB Copy 4761, Copy 10416, LB Memset 6896, Memset 10309, LB XOR 4524, XOR 1329
//
// ## Stage 2 (post optimization in full release) ##
// #asymmetric ciphers in operations per second, best of 4
// RingLWE: Gen 16666/33333, Enc 12500/16666, Dec 50000 +/+/+
// McEliece: Gen 12, Enc 12500, Dec 4577 =/+/+
//
// #symmetric ciphers in MB per second
// AHX: CTR , CBC , EAX , OFB , GCM
// SHX: CTR , CBC , EAX , OFB , GCM
// THX: CTR , CBC , EAX , OFB , GCM
// ChaCha: 
// Salsa: 
//
// #message digests in MB per second
// Blake2: 512- 728/1851, 256- 403/1605 +/=
// Keccak: 1024- 62/227, 512- 167/626, 256- 310/1149 -/+/=
// SHA2: 512- 352/1303, 256- 206/790 =/+
// Skein: 1024- 462/1904, 512- 331/1980, 256- 298/1426  +/+/+
//
// #memory in MB per second
// Memory: LB Clear 8849, Clear 10989, LB Copy 7633, Copy 9803, LB Memset 7575, Memset 10869, LB XOR 5181, XOR 1383
//
// ### 1.1.0.0 RoadMap ###
//
// AVX512 integration		-started
// RingLWE					-added
// McEliece					-added
// ModuleLWE				-?
// ECDH						-?
// RSA						-?
//
// GMSS						-?
// Tesla					-?
// RSA-Sig					-?
//
// TLS-KEX					-?
// P2P-KEX					-?
//
// Networking				-?
// Expand cpu/simd support	-?
// Android/Linux support	-?
// DLL API					-?


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
	ConsoleUtils::WriteLine("* CEX++ Version 1.0.1.3: CEX Library in C++  *");
	ConsoleUtils::WriteLine("*                                            *");
	ConsoleUtils::WriteLine("* Release:   v1.0.0.3 (A3)                   *");
	ConsoleUtils::WriteLine("* License:   GPLv3                           *");
	ConsoleUtils::WriteLine("* Date:      October 01, 2017                *");
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

	//RunTest(new SHAKETest());


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

#if (!defined(_M_X64) && !defined(__x86_64__)) && ((defined(__AVX__) || defined(__AVX2__)) && !defined(_DEBUG))
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