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
		RECT r;
		HWND console = GetConsoleWindow();
		GetWindowRect(console, &r);
		MoveWindow(console, r.left, r.top, 800, 800, TRUE);
		COORD newSize = { 200, 1000 };
		SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), newSize);
#else
		system("MODE CON COLS=120 LINES=80");
#endif
	}

	void ConsoleUtils::WriteLine(std::string Data)
	{
		std::cout << Data << std::endl;
	}
}