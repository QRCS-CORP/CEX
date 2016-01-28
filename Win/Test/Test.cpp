#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>

#include "AesAvsTest.h"
#include "AesFipsTest.h"
#include "BlakeTest.h"
#include "ChaChaTest.h"
#include "CipherModeTest.h"
#include "CipherStreamTest.h"
#include "CMACTest.h"
#include "ConsoleUtils.h"
#include "CTRDrbgTest.h"
#include "DigestStreamTest.h"
#include "ITest.h"
#include "HKDFTest.h"
#include "KDF2DrbgTest.h"
#include "HMACTest.h"
#include "HXCipherTest.h"
#include "ISCRsgTest.h"
#include "KeccakTest.h"
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
#include "SpeedTest.h"
#include "TwofishTest.h"
#include "VMACTest.h"
#include "XSPRsgTest.h"

#include "KeyGenerator.h"
#include "MemoryStream.h"
#include "CipherKey.h"
#include "MessageHeader.h"

using namespace Test;

// *** CEX 1.0 TODO ***
//
// add generators									-done
// add prngs										-done
// use test interface and local RunTest()			-done
// add padding tests								-done
// finish cmac and test								-done
// finish vmac and test								-done
// implement ex. CipherFromName helper classes		-done
// add DigestStream and MacStream + tests			-done
// fix cipherstream test							-done
// add progress events to xStream processors		-done
// sort out enum values and numbering				-done
// optimize chacha/salsa							-done
// add ISAAC and XSP seed generators				-done
// verify XSP + ISAAC vectors						-done
// serpent sboxes in serpent.h						-done
// Twofish Mix() function							-done
// implement XORBLK in modes (& mac?)				-done
// add all necessary cpp files						-done
// add keygenerator									-done
// all tests must throw on fail						-done
// add object enumeration type property				-done
// merge RDX+RHX, TFX+THX, SPX+SHX					-done
// add entropypool									-?
// add volumecipher									-?
// add keyfactory? 									-?
// add packagefactory?								-?
//

// change over test progress methods				-done
// cleanup tests (consolidate methods and style)	-done
// split test files and organize					-why split?
//
// fix sub-namespaces lookups						-?
// full code review									-almost
// review all documentation							-?
// update .Net CEX									-done
//
// classes left: 8?
// ETA: 2/1/16

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

void PrintHeader(std::string Data, std::string Decoration = "******")
{
	ConsoleUtils::WriteLine(Decoration + Data + Decoration);
}

void PrintTitle()
{
	ConsoleUtils::WriteLine("**********************************************");
	ConsoleUtils::WriteLine("* CEX++ Version 1.0: CEX Library in C++      *");
	ConsoleUtils::WriteLine("*                                            *");
	ConsoleUtils::WriteLine("* Release:   v1.0                            *");
	ConsoleUtils::WriteLine("* Date:      Jan 24, 2016                    *");
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
	catch (TestException ex)
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

void TestKeyGen()
{
	KeyGenerator kg;
	std::vector<byte> d(100);
	kg.GetBytes(d);
	KeyParams* kp;
	kp = kg.GetKeyParams(32, 0, 0);
	MemoryStream* m = KeyParams::Serialize(*kp);
	KeyParams kpc = KeyParams::DeSerialize(*m);
	delete m;
	if (!kp->Equals(kpc))
		throw;
	kp = kg.GetKeyParams(32, 0, 16);
	kp = kg.GetKeyParams(32, 16, 16);
	kp = kg.GetKeyParams(0, 16, 16);
	kp = kg.GetKeyParams(0, 0, 16);
}

int main(int argc, const char * argv[])
{
	ConsoleUtils::SizeConsole();
	PrintTitle();
	TestKeyGen();
	try
	{
		if (CanTest("Press 'Y' then Enter to run Speed Tests, any other key to cancel: "))
		{
			RunTest(new SpeedTest());
		}
		else
		{
			ConsoleUtils::WriteLine("Speed tests were Cancelled..");
		}
		ConsoleUtils::WriteLine("");

		if (!CanTest("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: "))
		{
			ConsoleUtils::WriteLine("Completed! Press any key to close..");
			GetResponse();
			return 0;
		}
		ConsoleUtils::WriteLine("");

		PrintHeader("TESTING SYMMETRIC BLOCK CIPHERS");
		RunTest(new AesAvsTest());
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
		PrintHeader("TESTING CRYPTOGRAPHIC HASH GENERATORS");
		RunTest(new BlakeTest());
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



