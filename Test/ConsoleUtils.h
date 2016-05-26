#ifndef _CEXTEST_CONSOLEUTILS_H
#define _CEXTEST_CONSOLEUTILS_H

#include <fstream>
#include <iostream>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#endif

class ConsoleUtils
{
public:
	static void SizeConsole()
	{
#ifdef _WIN32
		RECT r;
		HWND console = GetConsoleWindow();
		GetWindowRect(console, &r);
		MoveWindow(console, r.left, r.top, 800, 600, TRUE);
#endif
	}

	static void WriteLine(std::string Data)
	{
		std::cout << Data.c_str() << std::endl;
	}
};

#endif