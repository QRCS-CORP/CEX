#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <string>

#include "../../CEX/CpuDetect.h"
#include "../../Test/AEADTest.h"
#include "../../Test/AesAvsTest.h"
#include "../../Test/AesFipsTest.h"
#include "../../Test/Blake2Test.h"
#include "../../Test/ChaChaTest.h"
#include "../../Test/CipherModeTest.h"
#include "../../Test/CipherSpeedTest.h"
#include "../../Test/CipherStreamTest.h"
#include "../../Test/CMACTest.h"
#include "../../Test/ConsoleUtils.h"
#include "../../Test/CMGTest.h"
#include "../../Test/DCGTest.h"
#include "../../Test/DigestSpeedTest.h"
#include "../../Test/DigestStreamTest.h"
#include "../../Test/GMACTest.h"
#include "../../Test/KDF2Test.h"
#include "../../Test/KeccakTest.h"
#include "../../Test/HKDFTest.h"
#include "../../Test/HMACTest.h"
#include "../../Test/HMGTest.h"
#include "../../Test/HXCipherTest.h"
#include "../../Test/ITest.h"
#include "../../Test/MacStreamTest.h"
#include "../../Test/PaddingTest.h"
#include "../../Test/ParallelModeTest.h"
#include "../../Test/PBKDF2Test.h"
#include "../../Test/RangedRngTest.h"
#include "../../Test/RandomOutputTest.h"
#include "../../Test/RijndaelTest.h"
#include "../../Test/SalsaTest.h"
#include "../../Test/SCRYPTTest.h"
#include "../../Test/SecureStreamTest.h"
#include "../../Test/SerpentTest.h"
#include "../../Test/Sha2Test.h"
#include "../../Test/SkeinTest.h"
#include "../../Test/SymmetricKeyGeneratorTest.h"
#include "../../Test/SymmetricKeyTest.h"
#include "../../Test/TwofishTest.h"

using namespace Test;

// *** CEX 1.0 RoadMap ***
//
// Release 0.13
// HX kdf change		-done
// DCG/CMG/HMG Drbg		-done
// RDP/ECP/CJP provider -done
// Secure Key/mem		-done
// CipherStream rewrite	-done
// KeyGenerator rewrite	-dome

// Release 0.14.2.1
// EAX/GCM/OCB			-done
// GMAC					-done
// Code review			-done

// *** 1st Official Version: March 30, 2017 ***
//
// Release 1.0.0.1
// Skein Tree			-done
// Rewrite SHA2			-done
// Rewrite Blake2		-done
// Keccak Tree			-done
// Scrypt(maybe)		-done
// Code review			-done
// Help review			-done

// *** 1.1.0.0 RoadMap ***
//
// RingLWE				-?
// RLWE-SIG				-?
// McEliece				-?
// GMSS					-?
// RSA-Sig				-?
// Networking			-?
// TLS					-?
// STM-KEX				-?
// DLL API				-?

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
		return true;

	return false;
}

void PrintHeader(std::string Data, std::string Decoration = "***")
{
	ConsoleUtils::WriteLine(Decoration + Data + Decoration);
}

void PrintTitle()
{
	ConsoleUtils::WriteLine("**********************************************");
	ConsoleUtils::WriteLine("* CEX++ Version 1.0.0.1: CEX Library in C++  *");
	ConsoleUtils::WriteLine("*                                            *");
	ConsoleUtils::WriteLine("* Release:   v1.0.1.1 (A1)                   *");
	ConsoleUtils::WriteLine("* License:   GPLv3                           *");
	ConsoleUtils::WriteLine("* Date:      April 2, 2017                   *");
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
			ConsoleUtils::WriteLine(ex.Message());

		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("Continue Testing? Press 'Y' to continue, all other keys abort..");

		std::string resp;
		std::getline(std::cin, resp);
		std::transform(resp.begin(), resp.end(), resp.begin(), ::toupper);

		const std::string CONTINUE = "Y";
		if (resp.find(CONTINUE) == std::string::npos)
			CloseApp();
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

	Common::CpuDetect detect;
	bool hasAESNI = detect.AESNI();
	// older intels (<= i3) having some strange issues, until their fixed (soon) we skip tests..
	// we'll use avx2 availability to filter to only a subset of tests working on these older cpu's
	bool hasAVX2 = detect.AVX2();

	if (!hasAVX2)
	{
		PrintHeader("Warning! This library currently requires a minimum of AVX2 to support intrinsics!");
		PrintHeader("Cipher and Digest speed tests and some parallel tests will be disabled!");
		PrintHeader("", "");
	}

	try
	{
#if defined (_DEBUG)
		PrintHeader("Warning! Compile as Release with correct platform (x86/x64) for accurate timings");
		PrintHeader("", "");
#endif
		if (CanTest("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: "))
		{
			PrintHeader("TESTING SYMMETRIC BLOCK CIPHERS");
			if (hasAESNI)
			{
				PrintHeader("Testing the AES-NI implementation (AHX)");
				RunTest(new AesAvsTest(true));
			}
			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesAvsTest());
			if (hasAESNI)
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
			// not on i3..
			if (hasAVX2)
			{
				PrintHeader("TESTING PARALLEL CIPHER MODES");
				RunTest(new ParallelModeTest());
			}
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
			// sp and bp works fine on an i7, fails on i3? I'm workin on it..
			if (hasAVX2)
				RunTest(new Blake2Test());
			RunTest(new KeccakTest());
			RunTest(new SHA2Test());
			RunTest(new SkeinTest());
			PrintHeader("TESTING MESSAGE AUTHENTICATION CODE GENERATORS");
			RunTest(new CMACTest());
			RunTest(new HMACTest());
			PrintHeader("TESTING PSEUDO RANDOM NUMBER GENERATORS");
			RunTest(new RangedRngTest());
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
			// not on i3..
			if (hasAVX2)
				RunTest(new SymmetricKeyGeneratorTest());
			RunTest(new SecureStreamTest());
			RunTest(new SymmetricKeyTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Diagnostic tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");
		ConsoleUtils::WriteLine("");

		// blows up on an i3 w/ SSE?
		if (hasAVX2)
		{
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