#include "Common.h"
#include "ExampleUtils.h"
#include "FileEncryption.h"
#include "../../CEX/CpuDetect.h"

using namespace Example;

// Menu:
// Seperate this into another class with a unique header; make it a functional program
// Select a file: .cenc triggers key-file menu, if input file-name .cenc key-file is absent,
// ask for path, otherwise show key-file path, and enter (empty) triggers encryption menu.
// all other files generate key-generation menu (verify file name/path).
//
// encryption:
// encrypt this file ? y/n (all other chars do nothing)
// encryption result message success/fail
//
// decryption:
// decrypt this file ? y/n (all other chars do nothing)
// decryption result message success/fail
//
// key header:
// 1st byte, cipher type
// 1..17, nonce
// 18..eof, key

void CpuCheck()
{
	CEX::CpuDetect detect;
	ExampleUtils::WriteLine("L1 cache size: " + std::to_string(detect.L1CacheSize()));
	ExampleUtils::WriteLine("Total L1 cache size: " + std::to_string(detect.L1CacheTotal()));
	ExampleUtils::WriteLine("L1 cache line size: " + std::to_string(detect.L1CacheLineSize()));
	ExampleUtils::WriteLine("L2 cache size: " + std::to_string(detect.L2CacheSize()));
	ExampleUtils::WriteLine("Physical cores: " + std::to_string(detect.PhysicalCores()));
	ExampleUtils::WriteLine("Virtual cores: " + std::to_string(detect.VirtualCores()));
	ExampleUtils::WriteLine("HyperThreading: " + std::to_string(detect.HyperThread()));
	ExampleUtils::WriteLine("AES-NI: " + std::to_string(detect.AESNI()));
	ExampleUtils::WriteLine("AVX: " + std::to_string(detect.AVX()));
	ExampleUtils::WriteLine("AVX2: " + std::to_string(detect.AVX2()));
	ExampleUtils::WriteLine("CMUL: " + std::to_string(detect.CMUL()));
	ExampleUtils::WriteLine("RDRAND: " + std::to_string(detect.RDRAND()));
	ExampleUtils::WriteLine("RDTSCP: " + std::to_string(detect.RDTSCP()));
	ExampleUtils::WriteLine("SHA: " + std::to_string(detect.SHA()));
	ExampleUtils::WriteLine("SSE2: " + std::to_string(detect.SSE2()));
	ExampleUtils::WriteLine("SSE3: " + std::to_string(detect.SSE3()));
	ExampleUtils::WriteLine("SSSE3: " + std::to_string(detect.SSSE3()));
	ExampleUtils::WriteLine("SSE41: " + std::to_string(detect.SSE41()));
	ExampleUtils::WriteLine("SSE42: " + std::to_string(detect.SSE42()));
	ExampleUtils::WriteLine("XOP: " + std::to_string(detect.XOP()));
	ExampleUtils::WriteLine("");
}

std::string GetTime()
{
	time_t ret = time(nullptr);
	char str[26];
	ctime_s(str, sizeof(str), &ret);

	return std::string(str);
}

void PrintHeader(std::string Data, std::string Decoration = "***")
{
	ExampleUtils::WriteLine(Decoration + Data + Decoration);
}

void PrintTitle()
{
	ExampleUtils::WriteLine("************************************************");
	ExampleUtils::WriteLine("* CEX++ Library Examples and Usage Patterns	*");
	ExampleUtils::WriteLine("*                                              *");
	ExampleUtils::WriteLine("* Release:   v1.0.0.0							*");
	ExampleUtils::WriteLine("* License:   GPLv3                             *");
	ExampleUtils::WriteLine("* Date:      January 07, 2020                  *");
	ExampleUtils::WriteLine("* Contact:   develop@vtdev.com                 *");
	ExampleUtils::WriteLine("************************************************");
	ExampleUtils::WriteLine("");
}

void Terminate()
{
	std::string resp;

	PrintHeader("An error has occurred! Press any key to close..", "");
	ExampleUtils::WaitForInput();
	exit(0);
}

int main()
{
	std::string rbuf;

	ExampleUtils::SizeConsole();

#if !defined(_OPENMP)
	PrintHeader("Warning! This library requires OpenMP support, the test can not coninue!");
	PrintHeader("An error has occurred! Press any key to close..", "");
	ExampleUtils::WaitForInput();

	return 0;
#endif

	// main menu //

	try
	{
		FileEncryption::Help();
		FileEncryption::PrintTitle();
			
		while (true)
		{
			FileEncryption::Run();
			ExampleUtils::WriteLine("");
			ExampleUtils::WriteLine("Press Y and enter to encrypt another file, any other key to exit.");

			rbuf = ExampleUtils::GetResponse();

			if (rbuf != "y" && rbuf != "Y")
			{
				break;
			}
		}

		return 0;
	}
	catch (std::exception&)
	{
		PrintHeader("An error has occurred! Press any key to close..", "");
		ExampleUtils::WaitForInput();

		return 0;
	}
}