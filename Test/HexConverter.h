#ifndef _CEXTEST_HEXCONVERTER_H
#define _CEXTEST_HEXCONVERTER_H

#include <string.h>
#include <vector>
#include "Common.h"

namespace Test
{
    static std::vector<byte> _decodingTable;
    static std::vector<byte> _encodingTable;
    
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

				byte b1 = _decodingTable[Data[i++]];

                while (i < end && Ignore(Data[i]))
                    i++;

				byte b2 = _decodingTable[Data[i++]];
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
				temp[counter++] = _encodingTable[v >> 4];
				temp[counter++] = _encodingTable[v & 0xf];
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
			if (_decodingTable.size() == 0) 
			{
				_decodingTable.resize(128, 0);

				byte encodingBytes[16] =
				{
					(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
					(byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
				};

				_encodingTable.reserve(sizeof(encodingBytes));
				for (unsigned int i = 0; i < sizeof(encodingBytes); ++i)
					_encodingTable.push_back(encodingBytes[i]);

				for (unsigned int i = 0; i < _encodingTable.size(); i++)
					_decodingTable[_encodingTable[i]] = (byte)i;

				_decodingTable['A'] = _decodingTable['a'];
				_decodingTable['B'] = _decodingTable['b'];
				_decodingTable['C'] = _decodingTable['c'];
				_decodingTable['D'] = _decodingTable['d'];
				_decodingTable['E'] = _decodingTable['e'];
				_decodingTable['F'] = _decodingTable['f'];
			}
		}
    };
}

#endif

