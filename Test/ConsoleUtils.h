#ifndef _CEXTEST_CONSOLEUTILS_H
#define _CEXTEST_CONSOLEUTILS_H

#include <iostream>
#include <string>

#if defined(_WIN32)
#	include <Windows.h>
#else
#	include <cstdlib> 
#endif

class ConsoleUtils
{
public:
	static void SizeConsole()
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

	static void WriteLine(std::string Data)
	{
		std::cout << Data << std::endl;
	}
};

#endif