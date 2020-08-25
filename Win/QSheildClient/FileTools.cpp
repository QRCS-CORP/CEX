#include "FileTools.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>

namespace FileEncryptionService
{
	bool FileTools::Create(const std::string &FilePath)
	{
		bool ret;

		ret = false;
		std::ofstream file{ FilePath };

		if (Exists(FilePath))
		{
			ret = true;
		}

		return ret;
	}

	bool FileTools::Delete(const std::string &FilePath)
	{
		bool ret;

		ret = false;

		if (Exists(FilePath))
		{
			ret = (remove(FilePath.c_str()) == 0);
		}

		return ret;
	}

	bool FileTools::Erase(const std::string &FilePath)
	{
		bool ret;

		ret = false;

		if (Exists(FilePath))
		{
			std::ofstream ofs;
			ofs.open(FilePath, std::ofstream::out | std::ofstream::trunc);
			ofs.close();
			ret = true;
		}

		return ret;
	}

	bool FileTools::Exists(const std::string &FilePath)
	{
		bool ret;

		if (FilePath.size() != 0)
		{
			std::ifstream infile(FilePath.c_str());

			ret = infile.good();
			infile.close();
		}
		else
		{
			ret = false;
		}

		return ret;
	}

	size_t FileTools::Size(const std::string &FilePath)
	{
		size_t flen;

		flen = 0;

		if (Exists(FilePath))
		{
			std::ifstream in(FilePath, std::ifstream::ate | std::ifstream::binary);
			flen = static_cast<size_t>(in.tellg());
		}

		return flen;
	}

	bool FileTools::Read(const std::string &FilePath, std::vector<uint8_t> &Output)
	{
		bool ret;

		ret = false;

		if (Exists(FilePath))
		{
			std::ifstream input(FilePath, std::ios::binary);
			std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(input), {});
			input.close();

			Output.resize(buffer.size());
			std::copy(buffer.begin(), buffer.end(), Output.data());

			ret = true;
		}

		return ret;
	}

	bool FileTools::Write(const std::string &FilePath, const std::vector<uint8_t> &Input)
	{
		bool ret;

		ret = false;

		if (Exists(FilePath))
		{
			std::ofstream output(FilePath, std::ios::out | std::ios::binary);
			output.write((char*)Input.data(), Input.size());
			output.close();

			ret = true;
		}

		return ret;
	}
}