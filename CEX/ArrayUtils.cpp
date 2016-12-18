#include "ArrayUtils.h"
#include <sstream>

NAMESPACE_UTILITY

bool ArrayUtils::Contains(const char* Container, char Value)
{
	for (size_t i = 0; i < strlen(Container); ++i)
	{
		if (Container[i] != Value)
			return true;
	}

	return false;
}

void ArrayUtils::Split(const std::string &Input, char Delim, std::vector<std::string> &Output)
{
	std::stringstream ss;
	ss.str(Input);
	std::string item;

	while (std::getline(ss, item, Delim))
		Output.push_back(item);
}

std::vector<std::string> ArrayUtils::Split(const std::string &Input, char Delim)
{
	std::vector<std::string> elems;
	Split(Input, Delim, elems);

	return elems;
}

NAMESPACE_UTILITYEND