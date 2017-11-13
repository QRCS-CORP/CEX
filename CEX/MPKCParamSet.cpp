#include "MPKCParamSet.h"
#include "StreamReader.h"
#include "StreamWriter.h"

NAMESPACE_MCELIECE

//~~~Constructor~~~//

MPKCParamSet::MPKCParamSet()
	:
	GF(0),
	T(0),
	PublicKeySize(0),
	PrivateKeySize(0),
	ParamName(MPKCParams::None)
{
}

MPKCParamSet::MPKCParamSet(int Field, int Correction, uint PubKeySize, uint PriKeySize, MPKCParams ParamType)
	:
	GF(Field),
	T(Correction),
	PublicKeySize(PubKeySize),
	PrivateKeySize(PriKeySize),
	ParamName(ParamType)
{
}

MPKCParamSet::MPKCParamSet(const std::vector<byte> &ParamArray)
{
	IO::MemoryStream ms(ParamArray);
	IO::StreamReader reader(ms);

	GF = reader.ReadInt<uint>();
	ParamName = (MPKCParams)reader.ReadByte();
	PrivateKeySize = reader.ReadInt<uint>();
	PublicKeySize = reader.ReadInt<uint>();
	T = reader.ReadInt<uint>();
}

MPKCParamSet::~MPKCParamSet()
{
	Reset();
}

//~~~Public Functions~~~//

void MPKCParamSet::Load(int Field, int Correction, uint PubKeySize, uint PriKeySize, MPKCParams ParamType)
{
	GF = Field;
	T = Correction;
	ParamName = ParamType;
	PrivateKeySize = PriKeySize;
	PublicKeySize = PubKeySize;
}

void MPKCParamSet::Reset()
{
	GF = 0;
	T = 0;
	ParamName = MPKCParams::None;
	PrivateKeySize = 0;
	PublicKeySize = 0;
}

std::vector<byte> MPKCParamSet::ToBytes()
{
	IO::StreamWriter writer(17);

	writer.Write<uint>(GF);
	writer.Write<byte>(static_cast<byte>(ParamName));
	writer.Write<uint>(PrivateKeySize);
	writer.Write<uint>(PublicKeySize);
	writer.Write<uint>(T);

	return writer.GetBytes();
}

NAMESPACE_MCELIECEEND
