#include "ArrayTools.h"
#include <sstream>

NAMESPACE_TOOLS

bool ArrayTools::Contains(const char* Container, size_t Length, char Value)
{
	const char* x;
	size_t i;
	bool ret;

	ret = false;

	for (i = 0; i < Length; ++i)
	{
		x = Container + i;

		if (*x != Value)
		{
			ret = true;
		}
	}

	return ret;
}

void ArrayTools::Split(const std::string &Input, char Delimiter, std::vector<std::string> &Output)
{
	std::stringstream ss;
	ss.str(Input);
	std::string item;

	while (std::getline(ss, item, Delimiter))
	{
		Output.push_back(item);
	}
}

std::vector<std::string> ArrayTools::Split(const std::string &Input, char Delimiter)
{
	std::vector<std::string> elems;
	Split(Input, Delimiter, elems);

	return elems;
}

NAMESPACE_TOOLSEND
