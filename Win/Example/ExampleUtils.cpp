#include "ExampleUtils.h"
#include <iostream>
#include <stdio.h>
#if defined(_WIN32)
#	include <Windows.h>
#else
#	include <sys/types.h>
#	include <sys/time.h>
#endif

namespace Example
{
	std::string ExampleUtils::GetResponse()
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

	uint64_t ExampleUtils::GetTimeMs64()
	{
#if defined(_WIN32)
		// Windows
		int64_t ctr1 = 0;
		int64_t freq = 0;
		if (QueryPerformanceCounter((LARGE_INTEGER *)&ctr1) != 0)
		{
			QueryPerformanceFrequency((LARGE_INTEGER *)&freq);
			if (freq == 0)
			{
				throw;
			}
			// return microseconds to milliseconds
			return (uint64_t)(ctr1 * 1000.0 / freq);
		}
		else
		{
			FILETIME ft;
			LARGE_INTEGER li;

			// Get the amount of 100 nano seconds intervals elapsed since January 1, 1601 (UTC) and copy it to a LARGE_INTEGER structure
			GetSystemTimeAsFileTime(&ft);
			li.LowPart = ft.dwLowDateTime;
			li.HighPart = ft.dwHighDateTime;

			uint64_t ret = li.QuadPart;
			ret -= 116444736000000000LL; // Convert from file time to UNIX epoch time.
			ret /= 10000; // From 100 nano seconds (10^-7) to 1 millisecond (10^-3) intervals

			return ret;
		}
#else
		// Linux
		struct timeval tv;

		gettimeofday(&tv, NULL);
		uint64_t ret = tv.tv_usec;
		// Convert from micro seconds (10^-6) to milliseconds (10^-3)
		ret /= 1000;
		// Adds the seconds (10^0) after converting them to milliseconds (10^-3)
		ret += (tv.tv_sec * 1000);

		return ret;
#endif
	}

	void ExampleUtils::Print(const std::string &Data)
	{
		std::cout << Data << std::endl;
	}

	void ExampleUtils::SizeConsole()
	{
#if defined(_WIN32)
		try
		{
			RECT r;
			HWND console = GetConsoleWindow();
			GetWindowRect(console, &r);
			MoveWindow(console, r.left, r.top, 800, 800, TRUE);
			COORD newSize = { 200, 1000 };
			SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), newSize);
		}
		catch (std::exception&)
		{
		}
#else
		system("MODE CON COLS=120 LINES=80");
#endif
	}

	bool ExampleUtils::StringContains(const std::string &Content, const std::string &Term)
	{
		bool res;

		res = (Content.find(Term) != std::string::npos);
		
		return res;
	}

	void ExampleUtils::WaitForInput()
	{
		std::string resp = "";

		try
		{
			std::getline(std::cin, resp);
		}
		catch (std::exception&)
		{
		}
	}

	void ExampleUtils::WriteLine(const std::string &Data)
	{
		try
		{
			std::cout << Data << std::endl;
		}
		catch (std::exception&)
		{
		}
	}
}
