#include "ArrayTools.h"
#include <sstream>

NAMESPACE_UTILITY

bool ArrayTools::Contains(const char* Container, char Value)
{
	for (size_t i = 0; i < strlen(Container); ++i)
	{
		if (Container[i] != Value)
		{
			return true;
		}
	}

	return false;
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

NAMESPACE_UTILITYEND
