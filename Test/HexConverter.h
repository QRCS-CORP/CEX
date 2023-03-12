#ifndef CEXTEST_HEXCONVERTER_H
#define CEXTEST_HEXCONVERTER_H

#include "../CEX/CexDomain.h"

namespace Test
{
	/// <summary>
	/// A Hexadecimal conversion helper class
	/// </summary>
	class HexConverter final
	{
	public:

		static void Decode(const std::string &Input, std::vector<uint8_t> &Output);
		static void Decode(const std::vector<std::string> &Input, std::vector<std::vector<uint8_t>> &Output);
		static void Decode(const char* Input[], size_t Length, std::vector<std::vector<uint8_t>> &Output);
		static void Decode(const std::vector<std::string> &Input, size_t Length, std::vector<std::vector<uint8_t>> &Output);
		static void Encode(const std::vector<uint8_t> &Input, size_t Offset, size_t Length, std::vector<uint8_t> &Output);
		static void Encode(const std::vector<uint8_t> &Input, std::string &Output);
		static bool Ignore(char Value);
		static void Print(const std::string &Input, size_t Length = 128);
		static void Print(const std::vector<uint8_t> &Input, size_t Length = 128);
		static std::string ToString(const std::vector<uint8_t> &Input);
		static void ToString(const std::vector<uint8_t> &Input, std::string &Output);

	private:

		static const uint8_t ENCODING_TABLE[16];
		static std::vector<uint8_t> GetEncodingTable();
		static std::vector<uint8_t> GetDecodingTable();
	};
}

#endif

