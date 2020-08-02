#include "HexConverter.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>

namespace Test
{
	const byte HexConverter::ENCODING_TABLE[16] = 
	{
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
	};

	void HexConverter::Decode(const std::string &Input, std::vector<byte> &Output)
	{
		size_t end;
		size_t i(0);
		size_t j(0);
		size_t len(0);
		byte b1;
		byte b2;

		end = Input.size();
		Output.resize(end / 2, 0);

		while (end > 0)
		{
			if (!Ignore(Input[end - 1]))
			{
				break;
			}

			--end;
		}


		std::vector<byte> decTable = GetDecodingTable();

		while (i < end)
		{
			while (i < end && Ignore(Input[i]))
			{
				++i;
			}

			b1 = decTable[Input[i]];
			++i;

			while (i < end && Ignore(Input[i]))
			{
				++i;
			}

			b2 = decTable[Input[i]];
			++i;
			Output[j] = static_cast<byte>((b1 << 4) | b2);
			++j;
			++len;
		}
	}

	void HexConverter::Decode(const std::vector<std::string> &Input, std::vector<std::vector<byte>> &Output)
	{
		std::vector<byte> temp;
		size_t i;

		Output.clear();

		for (i = 0; i < Input.size(); ++i)
		{
			const std::string TMPSTR = Input[i];
			Decode(TMPSTR, temp);
			Output.push_back(temp);
		}
	}

	void HexConverter::Decode(const char* Input[], size_t Length, std::vector<std::vector<byte>> &Output)
	{
		std::vector<byte> dec;
		std::string enc;
		size_t i;

		Output.reserve(Length);

		for (i = 0; i < Length; ++i)
		{
			enc = Input[i];
			Decode(enc, dec);
			Output.push_back(dec);
		}
	}

	void HexConverter::Decode(const std::vector<std::string> &Input, size_t Length, std::vector<std::vector<byte>> &Output)
	{
		std::vector<byte> dec;
		std::string enc;
		size_t i;

		Output.reserve(Length);

		for (i = 0; i < Length; ++i)
		{
			enc = Input[i];
			Decode(enc, dec);
			Output.push_back(dec);
		}
	}

	void HexConverter::Encode(const std::vector<byte> &Input, size_t Offset, size_t Length, std::vector<byte> &Output)
	{
		const std::vector<byte> ENCTBL = GetEncodingTable();
		size_t ctr(0);
		size_t i;
		int vct;

		Output.resize(Length * 2, 0);

		for (i = Offset; i < (Offset + Length); ++i)
		{
			vct = Input[i];
			Output[ctr] = ENCTBL[vct >> 4];
			++ctr;
			Output[ctr] = ENCTBL[vct & 0x0F];
			++ctr;
		}
	}

	void HexConverter::Encode(const std::vector<byte> &Input, std::string &Output)
	{
		Output = ToString(Input);
	}

	bool HexConverter::Ignore(char Value)
	{
		return (Value == '\n' || Value == '\r' || Value == '\t' || Value == ' ');
	}

	void HexConverter::Print(const std::string &Input, size_t Length)
	{
		std::string tmp;
		size_t pos(0);
		size_t i;

		tmp.resize(128);

		for (i = 0; i < Input.size(); ++i)
		{
			if (i != 0 && i % Length == 0)
			{
				std::memcpy((void*)tmp.c_str(), Input.c_str() + pos, Length);
				std::transform(tmp.begin(), tmp.end(), tmp.begin(), std::ptr_fun<int, int>(toupper));
				std::cout << tmp <<  std::endl;
				pos += Length;
			}
		}

		const size_t RMDLEN = Input.size() - pos;

		if (RMDLEN != 0)
		{
			tmp.resize(RMDLEN);
			std::memcpy((void*)tmp.c_str(), Input.c_str() + pos, RMDLEN);
			std::transform(tmp.begin(), tmp.end(), tmp.begin(), std::ptr_fun<int, int>(toupper));
			std::cout << tmp << std::endl;
		}

		std::cout << std::endl;
	}

	void HexConverter::Print(const std::vector<byte> &Input, size_t Length)
	{
		std::string inp;
		std::string tmp;
		size_t i;
		size_t pos(0);

		inp = ToString(Input);
		tmp.resize(128);

		for (i = 0; i < inp.size(); ++i)
		{
			if (i != 0 && i % Length == 0)
			{
				std::memcpy((void*)tmp.c_str(), inp.c_str() + pos, Length);
				std::transform(tmp.begin(), tmp.end(), tmp.begin(), std::ptr_fun<int, int>(toupper));
				std::cout << tmp << std::endl;
				pos += Length;
			}
		}

		const size_t RMDLEN = inp.size() - pos;

		if (RMDLEN != 0)
		{
			tmp.resize(RMDLEN);
			std::memcpy((void*)tmp.c_str(), inp.c_str() + pos, RMDLEN);
			std::transform(tmp.begin(), tmp.end(), tmp.begin(), std::ptr_fun<int, int>(toupper));
			std::cout << tmp << std::endl;
		}

		std::cout << std::endl;
	}

	std::string HexConverter::ToString(const std::vector<byte> &Input)
	{
		std::vector<byte> enc;
		std::string otp("");

		Encode(Input, 0, Input.size(), enc);
		otp.assign(reinterpret_cast<char*>(&enc[0]), enc.size());

		return otp;
	}

	void HexConverter::ToString(const std::vector<byte> &Input, std::string &Output)
	{
		std::vector<byte> enc;

		Encode(Input, 0, Input.size(), enc);
		Output.assign(reinterpret_cast<char*>(&enc[0]), enc.size());
	}

	std::vector<byte> HexConverter::GetEncodingTable()
	{
		std::vector<byte> encTable;
		size_t i;

		encTable.reserve(sizeof(ENCODING_TABLE));

		for (i = 0; i < sizeof(ENCODING_TABLE); ++i)
		{
			encTable.push_back(ENCODING_TABLE[i]);
		}

		return encTable;
	}

	std::vector<byte> HexConverter::GetDecodingTable()
	{
		std::vector<byte> ENCTBL = GetEncodingTable();
		std::vector<byte> decTable(128, 0);
		size_t i;

		for (i = 0; i < ENCTBL.size(); i++)
		{
			decTable[ENCTBL[i]] = static_cast<byte>(i);
		}

		decTable['A'] = decTable['a'];
		decTable['B'] = decTable['b'];
		decTable['C'] = decTable['c'];
		decTable['D'] = decTable['d'];
		decTable['E'] = decTable['e'];
		decTable['F'] = decTable['f'];

		return decTable;
	}
}
