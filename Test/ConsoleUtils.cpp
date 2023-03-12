#include "ConsoleUtils.h"
#include <iostream>

#if defined(_WIN32)
#	include <Windows.h>
#else
#	include <cstdlib> 
#endif

namespace Test
{
	void ConsoleUtils::SizeConsole()
	{
#if defined(_WIN32)
		try
		{
			RECT r;
			HWND console = GetConsoleWindow();
			GetWindowRect(console, &r);
			MoveWindow(console, r.left, r.top, 900, 700, TRUE);
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

	void ConsoleUtils::WriteLine(const std::string &Data)
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
