#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>

#include "../CEX/Cpu.h"
#include "AesAvsTest.h"
#include "AesFipsTest.h"
#include "BlakeTest.h"
#include "Blake2Test.h"
#include "ChaChaTest.h"
#include "CipherModeTest.h"
#include "CipherStreamTest.h"
#include "CMACTest.h"
#include "ConsoleUtils.h"
#include "CTRDrbgTest.h"
#include "DigestSpeedTest.h"
#include "DigestStreamTest.h"
#include "HKDFTest.h"
#include "HMACTest.h"
#include "HXCipherTest.h"
#include "ITest.h"
#include "KDF2DrbgTest.h"
#include "ISCRsgTest.h"
#include "KeccakTest.h"
#include "KeyFactoryTest.h"
#include "MacStreamTest.h"
#include "PaddingTest.h"
#include "ParallelModeTest.h"
#include "PBKDF2Test.h"
#include "RangedRngTest.h"
#include "RijndaelTest.h"
#include "SalsaTest.h"
#include "SerpentTest.h"
#include "Sha2Test.h"
#include "SkeinTest.h"
#include "SP20DrbgTest.h"
#include "CipherSpeedTest.h"
#include "TwofishTest.h"
#include "VMACTest.h"
#include "XSPRsgTest.h"

using namespace Test;

// *** CEX 1.0 TODO ***
// EntropyPool			-?
// VolumeCipher			-?
// KeyFactory 			-?
// PackageFactory		-?
//
// *** CEX 2.0 TODO ***
// RingLWE				-?
// NTRU					-?
// Networking			-?
// DTM-KEX				-?
// TLS					-?

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
	ConsoleUtils::WriteLine("* CEX++ Version 1.1: CEX Library in C++      *");
	ConsoleUtils::WriteLine("*                                            *");
	ConsoleUtils::WriteLine("* Release:   v1.1f                           *");
	ConsoleUtils::WriteLine("* Date:      July 4, 2016                    *");
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

	try
	{
		PrintHeader("Warning! Compile as Release with correct platform (x86/x64) for accurate timings");
		PrintHeader("", "");

		if (CanTest("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: "))
		{
			PrintHeader("TESTING SYMMETRIC BLOCK CIPHERS");
			PrintHeader("Testing the AES-NI implementation (AHX)");
			if (CEX::Utility::Cpu::HasAESNI())
				RunTest(new AesAvsTest(true));
			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesAvsTest());
			PrintHeader("Testing the AES-NI implementation (AHX)");
			if (CEX::Utility::Cpu::HasAESNI())
				RunTest(new AesFipsTest(true));
			PrintHeader("Testing the AES software implementation (RHX)");
			RunTest(new AesFipsTest());
			RunTest(new RijndaelTest());
			RunTest(new SerpentTest());
			RunTest(new TwofishTest());
			PrintHeader("TESTING SYMMETRIC CIPHER MODES");
			RunTest(new CipherModeTest());
			PrintHeader("TESTING PARALLEL CIPHER MODES");
			RunTest(new ParallelModeTest());
			PrintHeader("TESTING CIPHER PADDING MODES");
			RunTest(new PaddingTest());
			PrintHeader("TESTING SYMMETRIC STREAM CIPHERS");
			RunTest(new ChaChaTest());
			RunTest(new SalsaTest());
			PrintHeader("TESTING HX EXTENDED CIPHERS");
			RunTest(new HXCipherTest());
			PrintHeader("TESTING CRYPTOGRAPHIC STREAM PROCESSORS");
			RunTest(new CipherStreamTest());
			RunTest(new DigestStreamTest());
			RunTest(new MacStreamTest());
			RunTest(new KeyFactoryTest());
			PrintHeader("TESTING CRYPTOGRAPHIC HASH GENERATORS");
			RunTest(new BlakeTest());
			RunTest(new Blake2Test());
			RunTest(new KeccakTest());
			RunTest(new SHA2Test());
			RunTest(new SkeinTest());
			PrintHeader("TESTING MESSAGE AUTHENTICATION CODE GENERATORS");
			RunTest(new CMACTest());
			RunTest(new HMACTest());
			RunTest(new VMACTest());
			PrintHeader("TESTING PSEUDO RANDOM NUMBER GENERATORS");
			RunTest(new RangedRngTest());
			PrintHeader("TESTING DETERMINISTIC RANDOM BYTE GENERATORS");
			RunTest(new CTRDrbgTest());
			RunTest(new HKDFTest());
			RunTest(new KDF2DrbgTest());
			RunTest(new PBKDF2Test());
			RunTest(new SP20DrbgTest());
			PrintHeader("TESTING PSEUDO RANDOM SEED GENERATORS");
			RunTest(new ISCRsgTest());
			RunTest(new XSPRsgTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Diagnostic tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");


		ConsoleUtils::WriteLine("");

		if (CanTest("Press 'Y' then Enter to run Symmetric Cipher Speed Tests, any other key to cancel: "))
		{
			RunTest(new CipherSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		// digests are currently being rewritten, so this can wait..
		/*if (CanTest("Press 'Y' then Enter to run Message Digest Speed Tests, any other key to cancel: "))
		{
			RunTest(new DigestSpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");*/

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