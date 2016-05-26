#ifndef _CEXTEST_HEXCONVERTER_H
#define _CEXTEST_HEXCONVERTER_H

#include <string.h>
#include <vector>
#include "Common.h"

namespace Test
{
    static std::vector<byte> m_decodingTable;
    static std::vector<byte> m_encodingTable;
    
    /// <summary>
    /// A Hexadecimal conversion helper class
    /// </summary>
    class HexConverter
    {
    public:
        static void Decode(const std::string &Data, std::vector<byte> &temp)
        {
            Initialize();

            unsigned int length = 0;
			unsigned int end = (unsigned int)Data.size();
            
            temp.resize(end / 2,0);

            while (end > 0)
            {
                if (!Ignore(Data[end - 1]))
                    break;

                end--;
            }

			unsigned int i = 0;
			unsigned int ct = 0;

            while (i < end)
            {

                while (i < end && Ignore(Data[i]))
                    i++;

				byte b1 = m_decodingTable[Data[i++]];

                while (i < end && Ignore(Data[i]))
                    i++;

				byte b2 = m_decodingTable[Data[i++]];
                temp[ct++] = (byte)((b1 << 4) | b2);
                length++;
            }
        }

        static void Decode(const std::vector<std::string> &Data, std::vector<std::vector<byte>> &result)
        {
            Initialize();
            
            result.clear();
            
            for (unsigned int i = 0; i < (unsigned int)Data.size(); ++i)
			{
                const std::string str=Data[i];
                std::vector<byte> temp;
                Decode(str, temp);
                result.push_back(temp);
            }
        }
        
        static void Decode(const char *encodedStrings[], size_t encodedSize, std::vector<std::vector<byte>> &result) 
		{
            result.reserve(encodedSize);
            
            for (unsigned int i = 0; i < encodedSize; ++i)
			{
                std::string encoded=encodedStrings[i];
                std::vector<byte> decoded;
                Decode(encoded, decoded);
                result.push_back(decoded);
            }
        }

		static void Encode(const std::vector<byte> &Data, unsigned int Offset, unsigned int Length, std::vector<byte> &temp)
		{
			Initialize();

			temp.resize(Length * 2, 0);

			int counter = 0;

			for (unsigned int i = Offset; i < (Offset + Length); i++)
			{
				int v = Data[i];
				temp[counter++] = m_encodingTable[v >> 4];
				temp[counter++] = m_encodingTable[v & 0xf];
			}
		}

		static void ToString(const std::vector<byte> &Data, std::string &result)
		{
			Initialize();

			std::vector<byte> encoded;
			Encode(Data, 0, (unsigned int)Data.size(), encoded);
			result.assign((char*)&encoded[0], encoded.size());
		}

    private:
        static bool Ignore(char C)
        {
            return (C == '\n' || C == '\r' || C == '\t' || C == ' ');
        }

		static void Initialize()
		{
			if (m_decodingTable.size() == 0) 
			{
				m_decodingTable.resize(128, 0);

				byte encodingBytes[16] =
				{
					(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
					(byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
				};

				m_encodingTable.reserve(sizeof(encodingBytes));
				for (unsigned int i = 0; i < sizeof(encodingBytes); ++i)
					m_encodingTable.push_back(encodingBytes[i]);

				for (unsigned int i = 0; i < m_encodingTable.size(); i++)
					m_decodingTable[m_encodingTable[i]] = (byte)i;

				m_decodingTable['A'] = m_decodingTable['a'];
				m_decodingTable['B'] = m_decodingTable['b'];
				m_decodingTable['C'] = m_decodingTable['c'];
				m_decodingTable['D'] = m_decodingTable['d'];
				m_decodingTable['E'] = m_decodingTable['e'];
				m_decodingTable['F'] = m_decodingTable['f'];
			}
		}
    };
}

#endif

