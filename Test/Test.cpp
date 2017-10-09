// HISTORY
//
// ### CEX 1.0.1.3 ###
// Release 1.0.1.3, October 1, 2017
// Pre-release of 1.0.0.4 spawned by bug fix
// Importance: Critical
// Bug found in RingLWE FFTQ12289N1024::GetNoise template
// Status: Fixed, and classes rewritten during optimization and security compliance review
//
// Release 1.0.0.4, On Schedule (eta. is mid October 2017)
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
// ###SCHEDULE FOR 1.0.0.4 RELEASE###
// ##ETA is October 22, 2017##
// Complete performance optimizations on all classes
// Complete security audit and rewrite
// Add Poly1305 MAC
// Make authenticated KEX changes to RingLWE
//
// ###JSF/MISRA/SEI CERT Check LIST###
// ##Local Changes##
// do not cast between different size integers (unless it would seriously/unavoidably impede performance)
// ensure that operations on signed integers do not result in overflow
// ensure that division and remainder operations do not result in divide-by-zero errors
// do not shift an expression by a negative number of bits or by greater than or equal to the number of bits that exist in the operand
// organize struct and class variable declarations by size large to small (avoid unnecessary padding)
// make all (public) functions const correct
// reduce the number of class level variables (consider performance vs safety)
// make as many class functions static as possible
// reduce the number of function parameters whenever possible
// replace macros with inline functions
// mark single parameter constructors as explicit
// replace all instances of pointer math (and C* pointers where practical)
// replace all C style casts with C++ equivalents, ex. static_cast<>() (except where it diminishes readability, ex. within array braces)
// compound integer operations should be expressed within parenthesis to statically define operation flow, ex.  a = (b * (c << 3))
// verify that all class scope variables are destroyed/reset in the destructor
// make the Destroy() functions private (confusing, and no need for them to be public)
// delete unused default/copy/move constructors from all structs and classes
// replace all macros with inline/templated functions
// on pointer comparisons replace '0' with nullptr (ex. y* != nullptr)
//
// ##Global Changes##
// all hex codes should be expressed in capitals, ex. 0xFF -done
// enum members should all be byte sized and sequential, i.e. 1,2,3.. (promote jump lists) -done
// reduce the number of global includes, and replace all C headers with C++ versions -done
// remove unused macros and defines in CEXCommon.h -done
// prefer static/extern const integers to #define -done
// add GNU header to each (major) header file
// move from C style pointers (*) to std::unique_ptr
//
// ##Upgrades##
// add GCM authentication mode to RingLWE
// add Padding property (and mechanism) to IAsymmetricCipher and children
// revise parallel options, replace Parallel parameter with cpu count (CpuCores), and make core count assignable

// ###Optimization Cycle 1: Sept 26, 2017###
// Performance of various algorithms pre/post memory and code optimizations
//
// ##Stage 1 (baseline)##
// #asymmetric ciphers in operations per second, best of 4
// RingLWE: Gen 14285/17345, Enc 10000/12547, Dec 33333
// McEliece: Gen 12, Enc 7692, Dec 4000
// #symmetric algorithms in MB per second
// AHX: ECB 11299, CTR 426/7633, ICM 172/8064, CBC 715/9803, CFB 352/2277, OFB 307, EAX 205/616, OCB 107/1013, GCM 311/1060
// SHX: ECB 2418
// THX: ECB 1002
// ChaCha: 6097
// Salsa: 6622
// Blake2: 512- 677/1831, 256- 376/1636
// Keccak: 1024- 79/314, 512- 155/400, 256- 294/1152
// SHA2: 512- 335/1312, 256- 193/788
// Skein: 1024- 350/1412, 512- 236/1204, 256- 221/929
// Memory: LB Clear 6993, Clear 10309, LB Copy 4761, Copy 10416, LB Memset 6896, Memset 10309, LB XOR 4524, XOR 1329
//
// ##Stage 2 (post optimization)##
// #asymmetric ciphers in operations per second, best of 4
// RingLWE: Gen 16666/33333, Enc 12500/16666, Dec 50000
// McEliece: Gen 12, Enc 12500, Dec 4577
// #symmetric algorithms in MB per second
// AHX: CTR , CBC , EAX , OFB , GCM
// SHX: CTR , CBC , EAX , OFB , GCM
// THX: CTR , CBC , EAX , OFB , GCM
// ChaCha: 
// Salsa: 
// Blake2: 512- , 256- 
// Keccak: 1024- , 512- , 256- 
// SHA2: 512- , 256- 
// Skein: 1024- , 512- , 256- 
// Memory: 
//
// ### 1.1.0.0 RoadMap ###
//
// AVX512 integration		-started
// RingLWE					-added
// McEliece					-added
// RSA						-?
// ModuleLWE				-?
// RSA-Sig					-?
// GMSS						-?
// TLS-KEX					-?
// P2P-KEX					-?
// DLL API					-?
// Android/Linux support	-?
// expand cpu/simd support	-?

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
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
	std::string resp;
	std::getline(std::cin, resp);

	return resp;
}

bool CanTest(std::string Message)
{
	ConsoleUtils::WriteLine(Message);
	std::string resp = GetResponse();
	std::transform(resp.begin(), resp.end(), resp.begin(), ::toupper);

	const std::string CONFIRM = "Y";
	if (resp.find(CONFIRM) != std::string::npos)
	{
		return true;
	}

	return false;
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
	catch (...) 
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

	Common::CpuDetect detect;

#if (!defined(_M_X64) && !defined(__x86_64__)) && ((defined(__AVX__) || defined(__AVX2__)) && !defined(_DEBUG))
	if (detect.IsX64() || detect.IsX86Emulation())
	{
		PrintHeader("Warning! Compiling x86/Release on a 64bit system using AVX/AVX2 will cause memory alignment errors.", "");
		PrintHeader("To test x86/Release, compile on a true x86 system, or disable enhanced instruction sets (arch:IA32), or run in x86/Debug mode.", "");
		PrintHeader("Tests aborted! Press any key to close..", "");
		GetResponse();

		return 0;
	}
#endif

	if (detect.AESNI())
	{
		PrintHeader("AES-NI intrinsics support has been detected on this system.");
	}
	else
	{
		PrintHeader("AES-NI intrinsics support was not detected on this system.");
	}
	PrintHeader("", "");

	if (detect.AVX2())
	{
#if !defined(__AVX2__)
		PrintHeader("Warning! AVX2 support was detected! Set the enhanced instruction set to arch:AVX2 for best performance.");
#else
		PrintHeader("AVX2 intrinsics support has been enabled.");
#endif
	}
	else if (detect.AVX())
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

			if (detect.AESNI())
			{
				PrintHeader("Testing the AES-NI implementation (AHX)");
				RunTest(new AesAvsTest(true));
			}
			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesAvsTest());
			if (detect.AESNI())
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
			RunTest(new HMACTest());
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
	catch (...)
	{
		PrintHeader("An error has occurred! Press any key to close..", "");
		GetResponse();

		return 0;
	}
}