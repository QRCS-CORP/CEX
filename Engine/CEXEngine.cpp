#include <fstream>
#include <iostream>
#include <stdio.h>
#include "TestUtils.h"

#include "AesFipsTest.h"
#include "AesAvsTest.h"
#include "BlakeTest.h"
#include "CipherModeTest.h"
#include "HkdfTest.h"
#include "HMacTest.h"
#include "HXCipherTest.h"
#include "KeccakTest.h"
#include "ParallelModeTest.h"
#include "RijndaelTest.h"
#include "SerpentTest.h"
#include "Sha2Test.h"
#include "SkeinTest.h"
#include "SpeedTest.h"
#include "TwofishTest.h"
#include "SalsaTest.h"
#include "ChaChaTest.h"

// ToDo: SpeedTest
// debug thx -done
// Check all copy() and memset() for zero byte
// remove usings?
// using std::?
// run through all tests again
// optimize for speed
// optimize for size
// replace std::vector<byte>
// serpent sboxes
// namespaces
// order of namespace/indef/include

// CEXCommon to config.h?
// verify aesavs vectors
// remove unnecessary headers
// add generators
// add prngs
// add macs
// add keygenerator
// update hmac (no keyparams)
// cleanup tests section (consolidate methods and style)

void PrintProjectHeader()
{
	std::cout << "**********************************************" << std::endl;
	std::cout << "* CEX Version 1.0 in C++                     *" << std::endl;
	std::cout << "*                                            *" << std::endl;
	std::cout << "* Release:   v1.0                            *" << std::endl;
	std::cout << "* Date:      Oct 26, 2015                    *" << std::endl;
	std::cout << "* Contact:   develop@vtdev.com               *" << std::endl;
	std::cout << "**********************************************" << std::endl;
	std::cout << "" << std::endl;
}

bool RunTest()
{
	std::string response;
	const std::string confirm = "y";

	std::getline(std::cin, response);
	std::transform(response.begin(), response.end(), response.begin(), ::tolower);

	if (response.find(confirm) != std::string::npos)
		return true;

	return false;
}

void SizeConsole()
{
#ifdef _WIN32
	RECT r;
	HWND console = GetConsoleWindow();
	GetWindowRect(console, &r);
	MoveWindow(console, r.left, r.top, 800, 600, TRUE);
#endif
}

int main(int argc, const char * argv[])
{
	SizeConsole();
	PrintProjectHeader();

	std::cout << "Press 'Y' then Enter to run Speed Tests, any other key to cancel: ";
	if (RunTest())
	{
		Test::SpeedTest spdTest;
		spdTest.Test();
	}
	else
	{
		std::cout << "Speed tests were Cancelled.." << std::endl;
	}
	std::cout << std::endl;

	std::cout << "Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: ";
	if (!RunTest())
	{
		std::cout << "Completed! Press any key to close.." << std::endl;
		std::cin.get();
		return 0;
	}
	std::cout << std::endl;

	std::cout << "***Testing Message Digest Implementations***" << std::endl;
	Test::BlakeTest blakeTest;
	blakeTest.Test();
	std::cout << std::endl;
	Test::KeccakTest keccakTest;
	keccakTest.Test();
	std::cout << std::endl;
	Test::SHA2Test sha2Test;
	sha2Test.Test();
	std::cout << std::endl;
	Test::SkeinTest skeinTest;
	skeinTest.Test();
	std::cout << std::endl;

	std::cout << "***Testing Message Authentication Code (MAC) Implementations***" << std::endl;
	Test::HMacTest hmacTest;
	hmacTest.Test();
	std::cout << std::endl;

	std::cout << "***Testing Deterministic Random Generator Implementations***" << std::endl;
	Test::HkdfTest hkdfTest;
	hkdfTest.Test();
	std::cout << std::endl;

	std::cout << "***Testing Stream Cipher Implementations***" << std::endl;
	Test::SalsaTest salsaTest;
	salsaTest.Test();
	std::cout << std::endl;
	Test::ChaChaTest chachaTest;
	chachaTest.Test();
	std::cout << std::endl;

	std::cout << "***Testing Symmetric Cipher Implementations (NIST 800-38A)***" << std::endl;
	Test::AesAvsTest aesAvsTest;
	aesAvsTest.Test();
	std::cout << std::endl;
	Test::RijndaelTest rijndaelTest;
	rijndaelTest.Test();
	std::cout << std::endl;
	Test::SerpentTest serpentTest;
	serpentTest.Test();
	std::cout << std::endl;
	Test::TwofishTest twofishTest;
	twofishTest.Test();
	std::cout << std::endl;

	std::cout << "***Testing Symmetric Cipher Mode Implementations***" << std::endl;
	Test::CipherModeTest cmtTest;
	cmtTest.Test();
	std::cout << std::endl;
	Test::ParallelModeTest pmTest;
	pmTest.Test();
	std::cout << std::endl;

	std::cout << "***Testing HX Cipher Implementations (CEX KAT)***" << std::endl;
	Test::HXCipherTest hxTest;
	hxTest.Test();
	std::cout << std::endl;

	std::cout << "Completed! Press any key to close..";
	std::cin.get();

	return 0;
}

