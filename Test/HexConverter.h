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

		static void Decode(const std::string &Input, std::vector<byte> &Output);
		static void Decode(const std::vector<std::string> &Input, std::vector<std::vector<byte>> &Output);
		static void Decode(const char *Input[], size_t Length, std::vector<std::vector<byte>> &Output);
		static void Decode(const std::vector<std::string> &Input, size_t Length, std::vector<std::vector<byte>> &Output);
		static void Encode(const std::vector<byte> &Input, size_t Offset, size_t Length, std::vector<byte> &Output);
		static bool Ignore(char Value);
		static void Print(const std::string &Input, size_t Length = 128);
		static void Print(const std::vector<byte> &Input, size_t Length = 128);
		static std::string ToString(const std::vector<byte> &Input);
		static void ToString(const std::vector<byte> &Input, std::string &Output);

	private:

		static const byte ENCODING_TABLE[16];
		static std::vector<byte> GetEncodingTable();
		static std::vector<byte> GetDecodingTable();
	};
}

#endif

