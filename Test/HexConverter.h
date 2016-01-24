#ifndef _CEXTEST_HexConverter_H
#define _CEXTEST_HexConverter_H

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
    private:
        static void Init()
		{
            if (_decodingTable.size() == 0) {
                _decodingTable.resize(128,0);
                
                byte encodingBytes[16]=
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

    public:
        /// <summary>
        /// Convert an array into a hex std::string
        /// </summary>
        /// 
        /// <param name="Data">Data to convert</param>
        /// 
        /// <returns>Data as a std::string</returns>
        static void ToString(const std::vector<byte> &Data, std::string &result)
        {
            Init();
            
            std::vector<byte> encoded;
            Encode(Data, 0, Data.size(), encoded);
            result.assign((char*)&encoded[0], encoded.size());
        }

        /// <summary>
        /// Encode an array of bytes in hexadecimal format
        /// </summary>
        /// 
        /// <param name="Data">The bytes to encode</param>
        /// <param name="Offset">The starting offset within the Data array</param>
        /// <param name="Length">The number of bytes to encode</param>
        /// 
        /// <returns>Encode bytes</returns>
        static void Encode(const std::vector<byte> &Data, int Offset, int Length, std::vector<byte> &temp)
        {
            Init();
            
            temp.resize(Length * 2,0);

            int counter = 0;

            for (int i = Offset; i < (Offset + Length); i++)
            {
                int v = Data[i];
                temp[counter++] = _encodingTable[v >> 4];
                temp[counter++] = _encodingTable[v & 0xf];
            }
        }

        /// <summary>
        /// Decode a Hex encoded std::string and return the output
        /// </summary>
        /// 
        /// <param name="Data">Hex std::string</param>
        /// 
        /// <returns>Decoded bytes</returns>
        static void Decode(const std::string &Data, std::vector<byte> &temp)
        {
            Init();
            
            byte b1, b2;
            int length = 0;
            int end = Data.size();
            
            temp.resize(end / 2,0);

            while (end > 0)
            {
                if (!Ignore(Data[end - 1]))
                    break;

                end--;
            }

            int i = 0;
            int ct = 0;

            while (i < end)
            {
                while (i < end && Ignore(Data[i]))
                    i++;

                b1 = _decodingTable[Data[i++]];

                while (i < end && Ignore(Data[i]))
                    i++;

                b2 = _decodingTable[Data[i++]];
                temp[ct++] = (byte)((b1 << 4) | b2);
                length++;
            }
        }

        static void Decode(const std::vector<std::string> &Data, std::vector<std::vector<byte>> &result)
        {
            Init();
            
            result.clear();
            
            for (unsigned int i = 0; i < Data.size(); ++i) {
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
        
    private:
        static bool Ignore(char C)
        {
            return (C == '\n' || C == '\r' || C == '\t' || C == ' ');
        }
    };
}

#endif

