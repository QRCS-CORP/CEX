// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#include "RLWEParamSet.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_RINGLWE

//~~~Constructor~~~//

RLWEParamSet::RLWEParamSet()
	:
	N(0),
	Q(0),
	ForwardMessageSize(0),
	ParamName(RLWEParams::None),
	ReturnMessageSize(0),
	SeedSize(0)
{}

RLWEParamSet::RLWEParamSet(uint Coefficients, int Modulus, uint SeedByteSize, uint ForwardByteSize, uint ReturnByteSize, RLWEParams ParamSet)
	:
	N(Coefficients),
	Q(Modulus),
	SeedSize(SeedByteSize),
	ForwardMessageSize(ForwardByteSize),
	ReturnMessageSize(ReturnByteSize),
	ParamName(ParamSet)
{
}

RLWEParamSet::RLWEParamSet(const std::vector<byte> &ParamArray)
{
	IO::MemoryStream ms = IO::MemoryStream(ParamArray);
	IO::StreamReader reader(ms);

	ForwardMessageSize = reader.ReadInt<uint>();
	N = reader.ReadInt<uint>();
	ParamName = (RLWEParams)reader.ReadInt<byte>();
	Q = reader.ReadInt<uint>();
	ReturnMessageSize = reader.ReadInt<uint>();
	SeedSize = reader.ReadInt<uint>();
}

RLWEParamSet::~RLWEParamSet()
{
	Reset();
}

//~~~Public Functions~~~//

void RLWEParamSet::Load(uint Coefficients, int Modulus, uint SeedByteSize, uint ForwardByteSize, uint ReturnByteSize, RLWEParams ParamSet)
{
	N = Coefficients;
	Q = Modulus;
	ForwardMessageSize = ForwardByteSize;
	ParamName = ParamName;
	ReturnMessageSize = ReturnByteSize;
	SeedSize = SeedByteSize;
}

void RLWEParamSet::Reset()
{
	N = 0;
	Q = 0;
	ForwardMessageSize = 0;
	ParamName = RLWEParams::None;
	ReturnMessageSize = 0;
	SeedSize = 0;
}

std::vector<byte> RLWEParamSet::ToBytes()
{
	IO::StreamWriter writer(21);

	writer.Write<uint>(ForwardMessageSize);
	writer.Write<uint>(N);
	writer.Write<byte>((byte)ParamName);
	writer.Write<uint>(Q);
	writer.Write<uint>(ReturnMessageSize);
	writer.Write<uint>(SeedSize);

	return writer.GetBytes();
}

NAMESPACE_RINGLWEEND