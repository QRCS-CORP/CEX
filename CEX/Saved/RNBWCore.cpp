#include "RNBWCore.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "RNBWGfMath.h"

NAMESPACE_RAINBOW

using Tools::IntegerTools;
using Digest::Keccak;
using Tools::MemoryTools;

class RNBWCore::RainbowParams
{
public:

	uint O1;
	uint O2;
	uint V1;
	uint V2;
	size_t HLen;
	size_t MaxO;
	size_t PriLen;
	size_t PubLen;
	size_t PubM;
	size_t PubN;
	size_t Rate;
	size_t SigLen;

	RainbowParams(RainbowParameters Params)
		:
		O1(0),
		O2(0),
		V1(0),
		V2(0),
		HLen(0),
		MaxO(0),
		PriLen(0),
		PubLen(0),
		PubM(0),
		PubN(0),
		Rate(0),
		SigLen(0)
	{
		SetParams(Params);
	}

	~RainbowParams()
	{
		HLen = 0;
		O1 = 0;
		O2 = 0;
		PriLen = 0;
		PubLen = 0;
		PubM = 0;
		PubN = 0;
		Rate = 0;
		SigLen = 0;
		V1 = 0;
		V2 = 0;
	}

	void SetParams(RainbowParameters Params)
	{
		switch (Params)
		{
			case RainbowParameters::RNBWS1S128SHAKE256:
			{
				O1 = 32;
				O2 = 32;
				V1 = 48;
				HLen = 32;
				PriLen = 277536;
				PubLen = 404992;
				Rate = Keccak::KECCAK256_RATE_SIZE;
				SigLen = 128;
				break;
			}
			case RainbowParameters::RNBWS3S256SHAKE512:
			{
				O1 = 48;
				O2 = 48;
				V1 = 92;
				HLen = 64;
				PriLen = 1227104;
				PubLen = 1705536;
				Rate = Keccak::KECCAK512_RATE_SIZE;
				SigLen = 204;
				break;
			}
			default:
			{
				// RNBWS2S192SHAKE512
				O1 = 36;
				O2 = 36;
				V1 = 68;
				HLen = 48;
				PriLen = 511448;
				PubLen = 710640;
				Rate = Keccak::KECCAK512_RATE_SIZE;
				SigLen = 156;
				break;
			}
		}

		PubM = static_cast<size_t>(O1) + O2;
		PubN = static_cast<size_t>(V1) + O1 + O2;
		V2 = V1 + O1;
		MaxO = (O1 > O2) ? O1 : O2;
	}

	static uint TriangleTerms(uint Val)
	{
		return (Val * (Val + 1)) / 2;
	}
};

class RNBWCore::RainbowPublicKey
{
public:

	std::vector<byte> L1Q1;
	std::vector<byte> L1Q2;
	std::vector<byte> L1Q3;
	std::vector<byte> L1Q5;
	std::vector<byte> L1Q6;
	std::vector<byte> L1Q9;
	std::vector<byte> L2Q1;
	std::vector<byte> L2Q2;
	std::vector<byte> L2Q3;
	std::vector<byte> L2Q5;
	std::vector<byte> L2Q6;
	std::vector<byte> L2Q9;
	size_t PkLen;

	RainbowPublicKey(RainbowParams &Params)
		:
		L1Q1(static_cast<size_t>(Params.O1) * RainbowParams::TriangleTerms(Params.V1)),
		L1Q2(static_cast<size_t>(Params.O1) * Params.V1 * Params.O1),
		L1Q3(static_cast<size_t>(Params.O1) * Params.V1 * Params.O2),
		L1Q5(static_cast<size_t>(Params.O1) * RainbowParams::TriangleTerms(Params.O1)),
		L1Q6(static_cast<size_t>(Params.O1) * Params.O1 * Params.O2),
		L1Q9(static_cast<size_t>(Params.O1) * RainbowParams::TriangleTerms(Params.O2)),
		L2Q1(static_cast<size_t>(Params.O2) * RainbowParams::TriangleTerms(Params.V1)),
		L2Q2(static_cast<size_t>(Params.O2) * Params.V1 * Params.O1),
		L2Q3(static_cast<size_t>(Params.O2) * Params.V1 * Params.O2),
		L2Q5(static_cast<size_t>(Params.O2) * RainbowParams::TriangleTerms(Params.O1)),
		L2Q6(static_cast<size_t>(Params.O2) * Params.O1 * Params.O2),
		L2Q9(static_cast<size_t>(Params.O2) * RainbowParams::TriangleTerms(Params.O2)),
		PkLen(Params.PubLen)
	{
	}

	~RainbowPublicKey()
	{
		MemoryTools::Clear(L1Q1, 0, L1Q1.size());
		MemoryTools::Clear(L1Q2, 0, L1Q2.size());
		MemoryTools::Clear(L1Q3, 0, L1Q3.size());
		MemoryTools::Clear(L1Q5, 0, L1Q5.size());
		MemoryTools::Clear(L1Q6, 0, L1Q6.size());
		MemoryTools::Clear(L1Q9, 0, L1Q9.size());
		MemoryTools::Clear(L2Q1, 0, L2Q1.size());
		MemoryTools::Clear(L2Q2, 0, L2Q2.size());
		MemoryTools::Clear(L2Q3, 0, L2Q3.size());
		MemoryTools::Clear(L2Q5, 0, L2Q5.size());
		MemoryTools::Clear(L2Q6, 0, L2Q6.size());
		MemoryTools::Clear(L2Q9, 0, L2Q9.size());
	}

	std::vector<byte> Serialize()
	{
		std::vector<byte> ret(PkLen);
		size_t oft;

		MemoryTools::Copy(L1Q1, 0, ret, 0, L1Q1.size());
		oft = L1Q1.size();
		MemoryTools::Copy(L1Q2, 0, ret, oft, L1Q2.size());
		oft += L1Q2.size();
		MemoryTools::Copy(L1Q3, 0, ret, oft, L1Q3.size());
		oft += L1Q3.size();
		MemoryTools::Copy(L1Q5, 0, ret, oft, L1Q5.size());
		oft += L1Q5.size();
		MemoryTools::Copy(L1Q6, 0, ret, oft, L1Q6.size());
		oft += L1Q6.size();
		MemoryTools::Copy(L1Q9, 0, ret, oft, L1Q9.size());
		oft += L1Q9.size();
		MemoryTools::Copy(L2Q1, 0, ret, oft, L2Q1.size());
		oft += L2Q1.size();
		MemoryTools::Copy(L2Q2, 0, ret, oft, L2Q2.size());
		oft += L2Q2.size();
		MemoryTools::Copy(L2Q3, 0, ret, oft, L2Q3.size());
		oft += L2Q3.size();
		MemoryTools::Copy(L2Q5, 0, ret, oft, L2Q5.size());
		oft += L2Q5.size();
		MemoryTools::Copy(L2Q6, 0, ret, oft, L2Q6.size());
		oft += L2Q6.size();
		MemoryTools::Copy(L2Q9, 0, ret, oft, L2Q9.size());

		return ret;
	}
};

class RNBWCore::RainbowSecretKey
{
public:

	std::vector<byte> SkSeed;
	std::vector<byte> S1;
	std::vector<byte> T1;
	std::vector<byte> T4;
	std::vector<byte> T3;
	std::vector<byte> L1F1;
	std::vector<byte> L1F2;
	std::vector<byte> L2F1;
	std::vector<byte> L2F2;
	std::vector<byte> L2F3;
	std::vector<byte> L2F5;
	std::vector<byte> L2F6;
	size_t SkLen;

	RainbowSecretKey(RainbowParams &Params)
		:
		SkSeed(RAINBOW_SKSEED_SIZE),
		S1(static_cast<size_t>(Params.O1) * Params.O2),
		T1(static_cast<size_t>(Params.V1) * Params.O1),
		T3(static_cast<size_t>(Params.O1) * Params.O2),
		T4(static_cast<size_t>(Params.V1) * Params.O2),
		L1F1(static_cast<size_t>(Params.O1) * Params.TriangleTerms(Params.V1)),
		L1F2(static_cast<size_t>(Params.O1) * Params.V1 * Params.O1),
		L2F1(static_cast<size_t>(Params.O2) * Params.TriangleTerms(Params.V1)),
		L2F2(static_cast<size_t>(Params.O2) * Params.V1 * Params.O1),
		L2F3(static_cast<size_t>(Params.O2) * Params.V1 * Params.O2),
		L2F5(static_cast<size_t>(Params.O2) * Params.TriangleTerms(Params.O1)),
		L2F6(static_cast<size_t>(Params.O2) * Params.O1 * Params.O2),
		SkLen(Params.PriLen)
	{
	}

	~RainbowSecretKey()
	{
		MemoryTools::Clear(SkSeed, 0, SkSeed.size());
		MemoryTools::Clear(S1, 0, S1.size());
		MemoryTools::Clear(T1, 0, T1.size());
		MemoryTools::Clear(T3, 0, T3.size());
		MemoryTools::Clear(T4, 0, T4.size());
		MemoryTools::Clear(L1F1, 0, L1F1.size());
		MemoryTools::Clear(L1F2, 0, L1F2.size());
		MemoryTools::Clear(L2F1, 0, L2F1.size());
		MemoryTools::Clear(L2F2, 0, L2F2.size());
		MemoryTools::Clear(L2F3, 0, L2F3.size());
		MemoryTools::Clear(L2F5, 0, L2F5.size());
		MemoryTools::Clear(L2F6, 0, L2F6.size());
	}

	static RainbowSecretKey Deserialize(RainbowParams &Params, const std::vector<byte> &Data)
	{
		RainbowSecretKey ret(Params);
		size_t oft;

		MemoryTools::Copy(Data, 0, ret.SkSeed, 0, ret.SkSeed.size());
		oft = ret.SkSeed.size();
		MemoryTools::Copy(Data, oft, ret.S1, 0, ret.S1.size());
		oft += ret.S1.size();
		MemoryTools::Copy(Data, oft, ret.T1, 0, ret.T1.size());
		oft += ret.T1.size();
		MemoryTools::Copy(Data, oft, ret.T4, 0, ret.T4.size());
		oft += ret.T4.size();
		MemoryTools::Copy(Data, oft, ret.T3, 0, ret.T3.size());
		oft += ret.T3.size();
		MemoryTools::Copy(Data, oft, ret.L1F1, 0, ret.L1F1.size());
		oft += ret.L1F1.size();
		MemoryTools::Copy(Data, oft, ret.L1F2, 0, ret.L1F2.size());
		oft += ret.L1F2.size();
		MemoryTools::Copy(Data, oft, ret.L2F1, 0, ret.L2F1.size());
		oft += ret.L2F1.size();
		MemoryTools::Copy(Data, oft, ret.L2F2, 0, ret.L2F2.size());
		oft += ret.L2F2.size();
		MemoryTools::Copy(Data, oft, ret.L2F3, 0, ret.L2F3.size());
		oft += ret.L2F3.size();
		MemoryTools::Copy(Data, oft, ret.L2F5, 0, ret.L2F5.size());
		oft += ret.L2F5.size();
		MemoryTools::Copy(Data, oft, ret.L2F6, 0, ret.L2F6.size());

		return ret;
	}

	static std::vector<byte> Serialize(RainbowParams &Params, RainbowSecretKey &PrivateKey)
	{
		std::vector<byte> ret(Params.PriLen);
		size_t oft;

		MemoryTools::Copy(PrivateKey.SkSeed, 0, ret, 0, PrivateKey.SkSeed.size());
		oft = PrivateKey.SkSeed.size();
		MemoryTools::Copy(PrivateKey.S1, 0, ret, oft, PrivateKey.S1.size());
		oft += PrivateKey.S1.size();
		MemoryTools::Copy(PrivateKey.T1, 0, ret, oft, PrivateKey.T1.size());
		oft += PrivateKey.T1.size();
		MemoryTools::Copy(PrivateKey.T4, 0, ret, oft, PrivateKey.T4.size());
		oft += PrivateKey.T4.size();
		MemoryTools::Copy(PrivateKey.T3, 0, ret, oft, PrivateKey.T3.size());
		oft += PrivateKey.T3.size();
		MemoryTools::Copy(PrivateKey.L1F1, 0, ret, oft, PrivateKey.L1F1.size());
		oft += PrivateKey.L1F1.size();
		MemoryTools::Copy(PrivateKey.L1F2, 0, ret, oft, PrivateKey.L1F2.size());
		oft += PrivateKey.L1F2.size();
		MemoryTools::Copy(PrivateKey.L2F1, 0, ret, oft, PrivateKey.L2F1.size());
		oft += PrivateKey.L2F1.size();
		MemoryTools::Copy(PrivateKey.L2F2, 0, ret, oft, PrivateKey.L2F2.size());
		oft += PrivateKey.L2F2.size();
		MemoryTools::Copy(PrivateKey.L2F3, 0, ret, oft, PrivateKey.L2F3.size());
		oft += PrivateKey.L2F3.size();
		MemoryTools::Copy(PrivateKey.L2F5, 0, ret, oft, PrivateKey.L2F5.size());
		oft += PrivateKey.L2F5.size();
		MemoryTools::Copy(PrivateKey.L2F6, 0, ret, oft, PrivateKey.L2F6.size());

		return ret;
	}
};

uint RNBWCore::IdxOfTrimat(size_t Row, size_t Column, size_t Dimension)
{
	// Calculate the corresponding index in an array for an upper-triangle(UT) matrix

	return static_cast<uint>((Dimension + Dimension - Row + 1) * Row / 2 + Column - Row);
}

uint RNBWCore::IdxOf2Trimat(size_t Row, size_t Column, size_t N)
{
	// Calculate the corresponding index in an array for an upper-triangle or lower-triangle matrix

	uint ret;

	if (Row > Column)
	{
		ret = IdxOfTrimat(Column, Row, N);
	}
	else
	{
		ret = IdxOfTrimat(Row, Column, N);
	}

	return ret;
}

void RNBWCore::UpperTrianglize(std::vector<byte> &Btric, const std::vector<byte> &Ba, size_t AWidth, size_t BatchSize)
{
	// Upper trianglize a rectangle matrix to the corresponding upper-trangle matrix

	size_t aheight;
	size_t coff;
	size_t i;
	size_t idx;
	size_t j;

	aheight = AWidth;
	coff = 0;

	for (i = 0; i < aheight; ++i)
	{
		for (j = 0; j < i; ++j)
		{
			idx = IdxOfTrimat(j, i, aheight);
			RNBWGfMath::Gf256vAdd(Btric, idx * BatchSize, Ba, BatchSize * (i * AWidth + j), BatchSize);
		}

		RNBWGfMath::Gf256vAdd(Btric, coff, Ba, BatchSize * (i * AWidth + i), BatchSize * (aheight - i));
		coff += BatchSize * (aheight - i);
	}
}

void RNBWCore::TrimatMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Btria, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize)
{
	// C += btriA * B , in GF(256)

	size_t awidth;
	size_t aheight;
	size_t aoff;
	size_t boff;
	size_t i;
	size_t j;
	size_t k;

	aoff = 0;
	boff = 0;
	awidth = BHeight;
	aheight = awidth;

	for (i = 0; i < aheight; ++i)
	{
		for (j = 0; j < BWidth; ++j)
		{
			for (k = 0; k < BHeight; ++k)
			{
				if (k < i)
				{
					continue;
				}

				RNBWGfMath::Gf256vMadd(Bc, boff, Btria, aoff + ((k - i) * BatchSize), RNBWGfMath::Gf256vGetEle(B, j * BColVecSize, static_cast<uint>(k)), BatchSize);
			}

			boff += BatchSize;
		}

		aoff += (aheight - i) * BatchSize;
	}
}

void RNBWCore::TrimatTrMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Btria, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize)
{
	// bC += btriA^Tr * B, in GF(256)

	size_t ahgt;
	size_t coff;
	size_t i;
	size_t j;
	size_t k;

	ahgt = BHeight;
	coff = 0;

	for (i = 0; i < ahgt; ++i)
	{
		for (j = 0; j < BWidth; ++j)
		{
			for (k = 0; k < BHeight; ++k)
			{
				if (i < k)
				{
					continue;
				}

				RNBWGfMath::Gf256vMadd(Bc, coff, Btria, BatchSize * (IdxOfTrimat(k, i, ahgt)), RNBWGfMath::Gf256vGetEle(B, j * BColVecSize, static_cast<uint>(k)), BatchSize);
			}

			coff += BatchSize;
		}
	}
}

void RNBWCore::Trimat2MaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Btria, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize)
{
	// bC += (btriA + btriA^Tr) *B, in GF(256)

	size_t ahgt;
	size_t coff;
	size_t i;
	size_t j;
	size_t k;

	ahgt = BHeight;
	coff = 0;

	for (i = 0; i < ahgt; ++i)
	{
		for (j = 0; j < BWidth; ++j)
		{
			for (k = 0; k < BHeight; ++k)
			{
				if (i == k)
				{
					continue;
				}

				RNBWGfMath::Gf256vMadd(Bc, coff, Btria, BatchSize * (IdxOf2Trimat(i, k, ahgt)), RNBWGfMath::Gf256vGetEle(B, j * BColVecSize, static_cast<uint>(k)), BatchSize);
			}

			coff += BatchSize;
		}
	}
}

void RNBWCore::MatTrMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &AtoTr, size_t AHeight, size_t AColVecSize, size_t AWidth, const std::vector<byte> &Bb, size_t BWidth, size_t BatchSize)
{
	// bC += A^Tr * Bb, in GF(256)

	size_t atrheight;
	size_t atrwidth;
	size_t coff;
	size_t i;
	size_t j;

	atrheight = AWidth;
	atrwidth = AHeight;
	coff = 0;

	for (i = 0; i < atrheight; ++i)
	{
		for (j = 0; j < atrwidth; ++j)
		{
			RNBWGfMath::Gf256vMadd(Bc, coff, Bb, j * BWidth * BatchSize, RNBWGfMath::Gf256vGetEle(AtoTr, AColVecSize * i, static_cast<uint>(j)), BatchSize * BWidth);
		}

		coff += BatchSize * BWidth;
	}
}

void RNBWCore::BmatTrMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &BaToTr, size_t AwidthBeforeTr, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize)
{
	// bC += bA^Tr * B, in GF(256)

	std::vector<byte> Ba;
	size_t ahgt;
	size_t coff;
	size_t i;
	size_t j;
	size_t k;

	Ba = BaToTr;
	ahgt = AwidthBeforeTr;
	coff = 0;

	for (i = 0; i < ahgt; ++i)
	{
		for (j = 0; j < BWidth; ++j)
		{
			for (k = 0; k < BHeight; ++k)
			{
				RNBWGfMath::Gf256vMadd(Bc, coff, Ba, BatchSize * (i + k * ahgt), RNBWGfMath::Gf256vGetEle(B, j * BColVecSize, static_cast<uint>(k)), BatchSize);
			}

			coff += BatchSize;
		}
	}
}

void RNBWCore::MatMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Ba, size_t AHeight, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize)
{
	// bC += bA * B, in GF(256)

	size_t aoff;
	size_t awdt;
	size_t coff;
	size_t i;
	size_t j;
	size_t k;

	aoff = 0;
	awdt = BHeight;
	coff = 0;

	for (i = 0; i < AHeight; ++i)
	{
		for (j = 0; j < BWidth; ++j)
		{
			for (k = 0; k < BHeight; ++k)
			{
				RNBWGfMath::Gf256vMadd(Bc, coff, Ba, aoff + (k * BatchSize), RNBWGfMath::Gf256vGetEle(B, j * BColVecSize, static_cast<uint>(k)), BatchSize);
			}

			coff += BatchSize;
		}

		aoff += awdt * BatchSize;
	}
}

void RNBWCore::QuadTrimatEvalGf256(std::vector<byte> &Y, const std::vector<byte> &TriMat, const std::vector<byte> &X, size_t XOffset, size_t Dim, size_t BatchSize)
{
	// Y =  X^Tr * TriMat * X, in GF(256)

	std::vector<byte> tmp(256);
	std::vector<byte> tmpx(256);
	size_t i;
	size_t j;
	size_t troff;

	for (i = 0; i < Dim; ++i)
	{
		tmpx[i] = RNBWGfMath::Gf256vGetEle(X, XOffset, static_cast<uint>(i));
	}

	RNBWGfMath::Gf256vSetZero(Y, 0, static_cast<uint>(BatchSize));
	troff = 0;

	for (i = 0; i < Dim; ++i)
	{
		RNBWGfMath::Gf256vSetZero(tmp, 0, static_cast<uint>(BatchSize));

		for (j = i; j < Dim; ++j)
		{
			RNBWGfMath::Gf256vMadd(tmp, 0, TriMat, troff, tmpx[j], BatchSize);
			troff += BatchSize;
		}

		RNBWGfMath::Gf256vMadd(Y, 0, tmp, 0, tmpx[i], BatchSize);
	}
}

void RNBWCore::QuadRecmatEvalGf256(std::vector<byte> &Z, const std::vector<byte> &Y, size_t DimY, const std::vector<byte> &Mat, const std::vector<byte> &X, size_t DimX, size_t BatchSize)
{
	// Z =  Y^Tr * Mat * X, in GF(256)

	std::vector<byte> tmp(128);
	std::vector<byte> tmpx(128);
	std::vector<byte> tmpy(128);
	size_t i;
	size_t j;
	size_t moff;

	for (i = 0; i < DimX; ++i)
	{
		tmpx[i] = RNBWGfMath::Gf256vGetEle(X, 0, static_cast<uint>(i));
	}

	for (i = 0; i < DimY; ++i)
	{
		tmpy[i] = RNBWGfMath::Gf256vGetEle(Y, 0, static_cast<uint>(i));
	}

	RNBWGfMath::Gf256vSetZero(Z, 0, static_cast<uint>(BatchSize));
	moff = 0;

	for (i = 0; i < DimY; ++i)
	{
		RNBWGfMath::Gf256vSetZero(tmp, 0, static_cast<uint>(BatchSize));

		for (j = 0; j < DimX; ++j)
		{
			RNBWGfMath::Gf256vMadd(tmp, 0, Mat, moff, tmpx[j], BatchSize);
			moff += BatchSize;
		}

		RNBWGfMath::Gf256vMadd(Z, 0, tmp, 0, tmpy[i], BatchSize);
	}
}

void RNBWCore::GenerateST(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed)
{
	// S1; domain seperate calls to xof
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.S1, 0, static_cast<size_t>(Params.O1) * Params.O2, Params.Rate);
	//stoff = Params.O1 * Params.O2;
	// T1
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.T1, 0, static_cast<size_t>(Params.V1) * Params.O1, Params.Rate);
	//stoff += Params.V1 * Params.O1;
	// T3
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.T4, 0, static_cast<size_t>(Params.V1) * Params.O2, Params.Rate);
	//MemoryTools::Copy(tmpst, 0, SandT, 0, tmpst.size());
	// T2
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.T3, 0, static_cast<size_t>(Params.O1) * Params.O2, Params.Rate);
	//stoff += Params.V1 * Params.O2;

}

void RNBWCore::GenerateL1F12(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed)
{
	// L1F1
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.L1F1, 0, static_cast<size_t>(Params.O1) * RainbowParams::TriangleTerms(Params.V1), Params.Rate);
	// L1F2
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.L1F2, 0, static_cast<size_t>(Params.O1) * Params.V1 * Params.O1, Params.Rate);
}

void RNBWCore::GenerateL2F12356(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed)
{
	// L2F1
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.L2F1, 0, static_cast<size_t>(Params.O2) * RainbowParams::TriangleTerms(Params.V1), Params.Rate);
	// L2F2
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.L2F2, 0, static_cast<size_t>(Params.O2) * Params.V1 * Params.O1, Params.Rate);
	// L2F3
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.L2F3, 0, static_cast<size_t>(Params.O2) * Params.V1 * Params.O2, Params.Rate);
	// L2F5
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.L2F5, 0, static_cast<size_t>(Params.O2) * RainbowParams::TriangleTerms(Params.O1), Params.Rate);
	// L2F6
	IntegerTools::BeIncrement8(Seed);
	XOF(Seed, 0, Seed.size(), Sk.L2F6, 0, static_cast<size_t>(Params.O2) * Params.O1 * Params.O2, Params.Rate);
}

void RNBWCore::GenerateB1B2(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed)
{
	GenerateL1F12(Params, Sk, Seed);
	GenerateL2F12356(Params, Sk, Seed);
}

void RNBWCore::CalculateT4(RainbowParams &Params, std::vector<byte> &T2toT4, const std::vector<byte> &T1, const std::vector<byte> &T3)
{
	// T4 = T_sk.T1 * T_sk.T3 - T_sk.t2

	std::vector<byte> temp(static_cast<size_t>(Params.V1) + 32);
	//std::vector<byte> T4;
	size_t i;
	size_t t3off;
	size_t t4off;

	t3off = 0;
	t4off = 0;

	for (i = 0; i < Params.O2; ++i)
	{
		// T3 width
		RNBWGfMath::Gf256MatProd(temp, T1, Params.V1, Params.O1, T3, t3off);
		RNBWGfMath::Gf256vAdd(T2toT4, t4off, temp, 0, Params.V1);
		t4off += Params.V1;
		t3off += Params.O1;
	}
}

void RNBWCore::ObsfucateL1Polys(RainbowParams &Params, std::vector<byte> &L1Polys, const std::vector<byte> &L2Polys, uint Terms, const std::vector<byte> &S1)
{
	std::vector<byte> temp(static_cast<size_t>(Params.O1) + 32);
	size_t l1off;
	size_t l2off;

	l1off = 0;
	l2off = 0;

	while (Terms != 0)
	{
		--Terms;
		RNBWGfMath::Gf256MatProd(temp, S1, Params.O1, Params.O2, L2Polys, l2off);
		RNBWGfMath::Gf256vAdd(L1Polys, l1off, temp, 0, Params.O1);
		l1off += Params.O1;
		l2off += Params.O2;
	}
}

void RNBWCore::GenerateSecretkeyHelper(RainbowParams &Params, RainbowSecretKey &Sk, const std::vector<byte> &SkSeed)
{
	// generating secret key with domain seperated shake
	MemoryTools::Copy(SkSeed, 0, Sk.SkSeed, 0, SkSeed.size());
	std::vector<byte> seed(RAINBOW_SKSEED_SIZE + 2);
	MemoryTools::Copy(SkSeed, 0, seed, 0, SkSeed.size());
	GenerateST(Params, Sk, seed);
	GenerateB1B2(Params, Sk, seed);
}

void RNBWCore::GenerateKeyPair(RainbowParams &Params, std::vector<byte> &Pk, std::vector<byte> &Sk, const std::vector<byte> &SkSeed)
{
	RainbowPublicKey tpk(Params);
	RainbowSecretKey tsk(Params);

	GenerateSecretkeyHelper(Params, tsk, SkSeed);

	//calculate_Q_from_F(pkp, skp, skp);
	CalculateQFromF(Params, tpk, tsk, tsk);

	// compute the public key in ext_cpk_t format
	CalculateT4(Params, tsk.T4, tsk.T1, tsk.T3);

	ObsfucateL1Polys(Params, tpk.L1Q1, tpk.L2Q1, Params.TriangleTerms(Params.V1), tsk.S1);
	ObsfucateL1Polys(Params, tpk.L1Q2, tpk.L2Q2, Params.V1 * Params.O1, tsk.S1);
	ObsfucateL1Polys(Params, tpk.L1Q3, tpk.L2Q3, Params.V1 * Params.O2, tsk.S1);
	ObsfucateL1Polys(Params, tpk.L1Q5, tpk.L2Q5, Params.TriangleTerms(Params.O1), tsk.S1);
	ObsfucateL1Polys(Params, tpk.L1Q6, tpk.L2Q6, Params.O1 * Params.O2, tsk.S1);
	ObsfucateL1Polys(Params, tpk.L1Q9, tpk.L2Q9, Params.TriangleTerms(Params.O2), tsk.S1);

	// so far, the pk contains the full pk but in ext_cpk_t format
	// convert the public key from ext_cpk_t to pk_t
	ExtCpkToPk(Params, Pk, tpk);
	Sk = RainbowSecretKey::Serialize(Params, tsk);
}

void RNBWCore::ExtCpkToPk(RainbowParams &Params, std::vector<byte> &Pk, const RainbowPublicKey &CPk)
{
	std::vector<byte> idxl1;
	std::vector<byte> idxl2;
	size_t i;
	size_t j;
	size_t l1off;
	size_t l2off;
	uint pubidx;

	l1off = 0;
	l2off = 0;
	idxl1 = CPk.L1Q1;
	idxl2 = CPk.L2Q1;

	for (i = 0; i < Params.V1; ++i)
	{
		for (j = i; j < Params.V1; ++j)
		{
			pubidx = IdxOfTrimat(i, j, Params.PubN);
			MemoryTools::Copy(idxl1, l1off, Pk, Params.PubM * pubidx, Params.O1);
			MemoryTools::Copy(idxl2, l2off, Pk, (Params.PubM * pubidx) + Params.O1, Params.O2);
			l1off += Params.O1;
			l2off += Params.O2;
		}
	}

	l1off = 0;
	l2off = 0;
	idxl1 = CPk.L1Q2;
	idxl2 = CPk.L2Q2;

	for (i = 0; i < Params.V1; ++i)
	{
		for (j = Params.V1; j < static_cast<size_t>(Params.V1) + Params.O1; ++j)
		{
			pubidx = IdxOfTrimat(i, j, Params.PubN);
			MemoryTools::Copy(idxl1, l1off, Pk, Params.PubM * pubidx, Params.O1);
			MemoryTools::Copy(idxl2, l2off, Pk, (Params.PubM * pubidx) + Params.O1, Params.O2);
			l1off += Params.O1;
			l2off += Params.O2;
		}
	}

	l1off = 0;
	l2off = 0;
	idxl1 = CPk.L1Q3;
	idxl2 = CPk.L2Q3;

	for (i = 0; i < Params.V1; ++i)
	{
		for (j = static_cast<size_t>(Params.V1) + Params.O1; j < Params.PubN; ++j)
		{
			pubidx = IdxOfTrimat(i, j, Params.PubN);
			MemoryTools::Copy(idxl1, l1off, Pk, Params.PubM * pubidx, Params.O1);
			MemoryTools::Copy(idxl2, l2off, Pk, (Params.PubM * pubidx) + Params.O1, Params.O2);
			l1off += Params.O1;
			l2off += Params.O2;
		}
	}

	l1off = 0;
	l2off = 0;
	idxl1 = CPk.L1Q5;
	idxl2 = CPk.L2Q5;

	for (i = Params.V1; i < static_cast<size_t>(Params.V1) + Params.O1; ++i)
	{
		for (j = i; j < static_cast<size_t>(Params.V1) + Params.O1; ++j)
		{
			pubidx = IdxOfTrimat(i, j, Params.PubN);
			MemoryTools::Copy(idxl1, l1off, Pk, Params.PubM * pubidx, Params.O1);
			MemoryTools::Copy(idxl2, l2off, Pk, (Params.PubM * pubidx) + Params.O1, Params.O2);
			l1off += Params.O1;
			l2off += Params.O2;
		}
	}

	l1off = 0;
	l2off = 0;
	idxl1 = CPk.L1Q6;
	idxl2 = CPk.L2Q6;

	for (i = Params.V1; i < static_cast<size_t>(Params.V1) + Params.O1; ++i)
	{
		for (j = static_cast<size_t>(Params.V1) + Params.O1; j < Params.PubN; ++j)
		{
			pubidx = IdxOfTrimat(i, j, Params.PubN);
			MemoryTools::Copy(idxl1, l1off, Pk, Params.PubM * pubidx, Params.O1);
			MemoryTools::Copy(idxl2, l2off, Pk, (Params.PubM * pubidx) + Params.O1, Params.O2);
			l1off += Params.O1;
			l2off += Params.O2;
		}
	}

	l1off = 0;
	l2off = 0;
	idxl1 = CPk.L1Q9;
	idxl2 = CPk.L2Q9;

	for (i = static_cast<size_t>(Params.V1) + Params.O1; i < Params.PubN; ++i)
	{
		for (j = i; j < Params.PubN; ++j)
		{
			pubidx = IdxOfTrimat(i, j, Params.PubN);
			MemoryTools::Copy(idxl1, l1off, Pk, Params.PubM * pubidx, Params.O1);
			MemoryTools::Copy(idxl2, l2off, Pk, (Params.PubM * pubidx) + Params.O1, Params.O2);
			l1off += Params.O1;
			l2off += Params.O2;
		}
	}
}

void RNBWCore::CalculateQFromF(RainbowParams &Params, RainbowPublicKey &Qs, const RainbowSecretKey &Fs, const RainbowSecretKey &Ts)
{
	std::vector<byte> tmpq;
	size_t qsize;

	// Layer 1 Computing :
	// Q_pk.l1_F1s[i] = F_sk.l1_F1s[i]
	// Q_pk.l1_F2s[i] = (F1* T1 + F2) + F1tr * T1
	// Q_pk.l1_F5s[i] = UT( T1tr* (F1 * T1 + F2))

	MemoryTools::Copy(Fs.L1F1, 0, Qs.L1Q1, 0, static_cast<size_t>(Params.O1) * Params.TriangleTerms(Params.V1));
	MemoryTools::Copy(Fs.L1F2, 0, Qs.L1Q2, 0, static_cast<size_t>(Params.O1) * Params.V1 * Params.O1);
	// F1*T1 + F2
	TrimatMaddGf256(Qs.L1Q2, Fs.L1F1, Ts.T1, Params.V1, Params.V1, Params.O1, Params.O1);
	// needed?
	MemoryTools::Clear(Qs.L1Q3, 0, static_cast<size_t>(Params.O1) * Params.V1 * Params.O2);
	MemoryTools::Clear(Qs.L1Q5, 0, static_cast<size_t>(Params.O1) * Params.TriangleTerms(Params.O1));
	MemoryTools::Clear(Qs.L1Q6, 0, static_cast<size_t>(Params.O1) * Params.O1 * Params.O2);
	MemoryTools::Clear(Qs.L1Q9, 0, static_cast<size_t>(Params.O1) * Params.TriangleTerms(Params.O2));

	qsize = static_cast<size_t>(Params.O1) * Params.O1 * Params.O1;

	if (static_cast<size_t>(Params.O1) * Params.O2 * Params.O2 > qsize)
	{
		qsize = static_cast<size_t>(Params.O1) * Params.O2 * Params.O2;
	}

	if (static_cast<size_t>(Params.O2) * Params.O1 * Params.O1 > qsize)
	{
		qsize = static_cast<size_t>(Params.O2) * Params.O1 * Params.O1;
	}

	if (static_cast<size_t>(Params.O2) * Params.O2 * Params.O2 > qsize)
	{
		qsize = static_cast<size_t>(Params.O2) * Params.O2 * Params.O2;
	}

	tmpq.resize(qsize + 32);

	// t1_tr*(F1*T1 + F2)
	MatTrMaddGf256(tmpq, Ts.T1, Params.V1, Params.V1, Params.O1, Qs.L1Q2, Params.O1, Params.O1);
	// UT( ... ) Q5
	UpperTrianglize(Qs.L1Q5, tmpq, Params.O1, Params.O1);
	// Q2
	TrimatTrMaddGf256(Qs.L1Q2, Fs.L1F1, Ts.T1, Params.V1, Params.V1, Params.O1, Params.O1);

	// Computing:
	// F1_T2 = F1 * t2
	// F2_T3 = F2 * T3
	// F1_F1T_T2 + F2_T3 = F1_T2 + F2_T3 + F1tr * t2
	// Q_pk.l1_F3s[i] = F1_F1T_T2 + F2_T3
	// Q_pk.l1_F6s[i] = T1tr*( F1_F1T_T2 + F2_T3 ) + F2tr * t2
	// Q_pk.l1_F9s[i] = UT( T2tr* ( F1_T2 + F2_T3 ) )

	// F1*T2
	TrimatMaddGf256(Qs.L1Q3, Fs.L1F1, Ts.T4, Params.V1, Params.V1, Params.O2, Params.O1);
	// F1_T2 + F2_T3
	MatMaddGf256(Qs.L1Q3, Fs.L1F2, Params.V1, Ts.T3, Params.O1, Params.O1, Params.O2, Params.O1);
	// L1Q9
	MemoryTools::Clear(tmpq, 0, static_cast<size_t>(Params.O1) * Params.O2 * Params.O2);
	// T2tr * ( F1_T2 + F2_T3 ) */
	MatTrMaddGf256(tmpq, Ts.T4, Params.V1, Params.V1, Params.O2, Qs.L1Q3, Params.O2, Params.O1);
	// Q9
	UpperTrianglize(Qs.L1Q9, tmpq, Params.O2, Params.O1);
	// F1_F1T_T2 + F2_T3 Q3
	TrimatTrMaddGf256(Qs.L1Q3, Fs.L1F1, Ts.T4, Params.V1, Params.V1, Params.O2, Params.O1);
	// F2tr*T2
	BmatTrMaddGf256(Qs.L1Q6, Fs.L1F2, Params.O1, Ts.T4, Params.V1, Params.V1, Params.O2, Params.O1);
	// Q6
	MatTrMaddGf256(Qs.L1Q6, Ts.T1, Params.V1, Params.V1, Params.O1, Qs.L1Q3, Params.O2, Params.O1);

	// layer 2
	// Computing:
	// Q1 = F1
	// Q2 = F1_F1T*T1 + F2
	// Q5 = UT( T1tr( F1*T1 + F2 )  + F5 )

	MemoryTools::Copy(Fs.L2F1, 0, Qs.L2Q1, 0, static_cast<size_t>(Params.O2) * Params.TriangleTerms(Params.V1));
	MemoryTools::Copy(Fs.L2F2, 0, Qs.L2Q2, 0, static_cast<size_t>(Params.O2) * Params.V1 * Params.O1);
	// F1*T1 + F2
	TrimatMaddGf256(Qs.L2Q2, Fs.L2F1, Ts.T1, Params.V1, Params.V1, Params.O1, Params.O2);
	MemoryTools::Copy(Fs.L2F5, 0, Qs.L2Q5, 0, static_cast<size_t>(Params.O2) * Params.TriangleTerms(Params.O1));
	// L2Q5
	MemoryTools::Clear(tmpq, 0, static_cast<size_t>(Params.O2) * Params.O1 * Params.O1);
	// t1_tr*(F1*T1 + F2)
	MatTrMaddGf256(tmpq, Ts.T1, Params.V1, Params.V1, Params.O1, Qs.L2Q2, Params.O1, Params.O2);
	// UT( ... ) Q5
	UpperTrianglize(Qs.L2Q5, tmpq, Params.O1, Params.O2);
	// Q2
	TrimatTrMaddGf256(Qs.L2Q2, Fs.L2F1, Ts.T1, Params.V1, Params.V1, Params.O1, Params.O2);

	// Computing:
	// F1_T2 = F1 * t2
	// F2_T3 = F2 * T3
	// F1_F1T_T2 + F2_T3 = F1_T2 + F2_T3 + F1tr * t2
	// Q3 =F1_F1T*T2 + F2*T3 + F3
	// Q9 = UT( T2tr*( F1*T2 + F2*T3 + F3 ) + T3tr*( F5*T3 + F6 ) )
	// Q6 = T1tr*( F1_F1T*T2 + F2*T3 + F3 ) + F2Tr*T2 + F5_F5T*T3 + F6

	MemoryTools::Copy(Fs.L2F3, 0, Qs.L2Q3, 0, static_cast<size_t>(Params.O2) * Params.V1 * Params.O2);
	// F1*T2 + F3
	TrimatMaddGf256(Qs.L2Q3, Fs.L2F1, Ts.T4, Params.V1, Params.V1, Params.O2, Params.O2);
	// F1_T2 + F2_T3 + F3
	MatMaddGf256(Qs.L2Q3, Fs.L2F2, Params.V1, Ts.T3, Params.O1, Params.O1, Params.O2, Params.O2);
	// L2Q9
	MemoryTools::Clear(tmpq, 0, static_cast<size_t>(Params.O2) * Params.O2 * Params.O2);
	// T2tr * ( ..... )
	MatTrMaddGf256(tmpq, Ts.T4, Params.V1, Params.V1, Params.O2, Qs.L2Q3, Params.O2, Params.O2);
	MemoryTools::Copy(Fs.L2F6, 0, Qs.L2Q6, 0, static_cast<size_t>(Params.O2) * Params.O1 * Params.O2);
	// F5*T3 + F6
	TrimatMaddGf256(Qs.L2Q6, Fs.L2F5, Ts.T3, Params.O1, Params.O1, Params.O2, Params.O2);
	// T2tr*( ..... ) + T3tr*( ..... )
	MatTrMaddGf256(tmpq, Ts.T3, Params.O1, Params.O1, Params.O2, Qs.L2Q6, Params.O2, Params.O2);
	MemoryTools::Clear(Qs.L2Q9, 0, static_cast<size_t>(Params.O2) * Params.TriangleTerms(Params.O2));

	// Q9
	UpperTrianglize(Qs.L2Q9, tmpq, Params.O2, Params.O2);
	// F1_F1T_T2 + F2_T3 + F3 - Q3
	TrimatTrMaddGf256(Qs.L2Q3, Fs.L2F1, Ts.T4, Params.V1, Params.V1, Params.O2, Params.O2);
	// F5*T3 + F6 +  F2tr*T2
	BmatTrMaddGf256(Qs.L2Q6, Fs.L2F2, Params.O1, Ts.T4, Params.V1, Params.V1, Params.O2, Params.O2);
	// F2tr*T2 + F5_F5T*T3 + F6
	TrimatTrMaddGf256(Qs.L2Q6, Fs.L2F5, Ts.T3, Params.O1, Params.O1, Params.O2, Params.O2);
	// Q6
	MatTrMaddGf256(Qs.L2Q6, Ts.T1, Params.V1, Params.V1, Params.O1, Qs.L2Q3, Params.O2, Params.O2);
}

void RNBWCore::CalculateQfromF(RainbowParams &Params, RainbowPublicKey &Qs, const RainbowSecretKey &Fs, const RainbowSecretKey &Ts)
{
	CalculateQFromF(Params, Qs, Fs, Ts);
}

int32_t RNBWCore::RainbowSignClassic(RainbowParams &Params, std::vector<byte> &Signature, const RainbowSecretKey &Sk, const std::vector<byte> &Digest)
{
	std::vector<byte> digestsalt(Params.HLen + RAINBOW_SALT_BYTE);
	std::vector<byte> matbuffer(2 * Params.MaxO * Params.MaxO);
	std::vector<byte> matl1(static_cast<size_t>(Params.O1) * Params.O1);
	std::vector<byte> matl2(static_cast<size_t>(Params.O2) * Params.O2);
	std::vector<byte> matl2F3;
	std::vector<byte> matl2F2;
	std::vector<byte> preseed(RAINBOW_LEN_SKSEED + Params.HLen);
	std::vector<byte> rl1F1(Params.O1);
	std::vector<byte> rl2F1(Params.O2);
	std::vector<byte> salt(RAINBOW_SALT_BYTE);
	std::vector<byte> seed(Params.HLen + 2);
	std::vector<byte> tempo(Params.MaxO + 32);
	std::vector<byte> vinegar(Params.V1);
	std::vector<byte> w(Params.PubN);
	std::vector<byte> xo1(Params.O1);
	std::vector<byte> xo2(Params.O1);
	std::vector<byte> y(Params.PubM);
	std::vector<byte> z(Params.PubM);
	const size_t SIGOFF = Signature.size() - Params.SigLen;
	uint l1succ(0);
	uint nattempt(0);
	uint succ(0);
	int32_t ret(0);

	MemoryTools::Copy(Sk.SkSeed, 0, preseed, 0, RAINBOW_LEN_SKSEED);
	MemoryTools::Copy(Digest, 0, preseed, RAINBOW_LEN_SKSEED, Params.HLen);
	XOF(preseed, 0, preseed.size(), seed, 0, seed.size(), Params.Rate);

	// roll vinegars
	while (l1succ == 0)
	{
		if (RAINBOW_MAX_ATTEMPT_FRMAT <= nattempt)
		{
			break;
		}

		// generating vinegars
		IntegerTools::BeIncrement8(seed);
		XOF(seed, 0, seed.size(), vinegar, 0, vinegar.size(), Params.Rate);
		// generating the linear equations for layer 1
		RNBWGfMath::Gf256MatProd(matl1, Sk.L1F2, Params.O1 * Params.O1, Params.V1, vinegar, 0);
		// check if the linear equation solvable
		l1succ = RNBWGfMath::Gf256MatInv(matl1, matl1, Params.O1, matbuffer);
		++nattempt;
	}

	// Given the vinegars, pre-compute variables needed for layer 2
	QuadTrimatEvalGf256(rl1F1, Sk.L1F1, vinegar, 0, Params.V1, Params.O1);
	QuadTrimatEvalGf256(rl2F1, Sk.L2F1, vinegar, 0, Params.V1, Params.O2);
	matl2F3.resize(static_cast<size_t>(Params.O2) * Params.O2);
	matl2F2.resize(static_cast<size_t>(Params.O1) * Params.O2);
	RNBWGfMath::Gf256MatProd(matl2F3, Sk.L2F3, Params.O2 * Params.O2, Params.V1, vinegar, 0);
	RNBWGfMath::Gf256MatProd(matl2F2, Sk.L2F2, Params.O1 * Params.O2, Params.V1, vinegar, 0);
	MemoryTools::Copy(Digest, 0, digestsalt, 0, Params.HLen);

	while (succ == 0)
	{
		if (RAINBOW_MAX_ATTEMPT_FRMAT <= nattempt)
		{
			break;
		}

		// The computation: H(Digest||salt) --> z --S--> y --C-map--> x --T--> w -roll the salt
		IntegerTools::BeIncrement8(seed);
		XOF(seed, 0, seed.size(), salt, 0, salt.size(), Params.Rate);
		MemoryTools::Copy(salt, 0, digestsalt, Params.HLen, salt.size());
		XOF(digestsalt, 0, digestsalt.size(), z, 0, z.size(), Params.Rate);
		// y = S^-1 * z
		MemoryTools::Copy(z, 0, y, 0, z.size());
		// identity part of S
		RNBWGfMath::Gf256MatProd(tempo, Sk.S1, Params.O1, Params.O2, z, Params.O1);
		RNBWGfMath::Gf256vAdd(y, 0, tempo, 0, Params.O1);

		// Central Map:
		// layer 1: calculate xo1
		MemoryTools::Copy(rl1F1, 0, tempo, 0, Params.O1);
		RNBWGfMath::Gf256vAdd(tempo, 0, y, 0, Params.O1);
		RNBWGfMath::Gf256MatProd(xo1, matl1, Params.O1, Params.O1, tempo, 0);
		// layer 2: calculate xo2
		RNBWGfMath::Gf256vSetZero(tempo, 0, Params.O2);
		// F2
		RNBWGfMath::Gf256MatProd(tempo, matl2F2, Params.O2, Params.O1, xo1, 0);
		// F5
		QuadTrimatEvalGf256(matl2, Sk.L2F5, xo1, 0, Params.O1, Params.O2);
		RNBWGfMath::Gf256vAdd(tempo, 0, matl2, 0, Params.O2);
		// F1
		RNBWGfMath::Gf256vAdd(tempo, 0, rl2F1, 0, Params.O2);
		RNBWGfMath::Gf256vAdd(tempo, 0, y, Params.O1, Params.O2);
		// generate the linear equations of the 2nd layer
		// F6
		RNBWGfMath::Gf256MatProd(matl2, Sk.L2F6, Params.O2 * Params.O2, Params.O1, xo1, 0);
		// F3
		RNBWGfMath::Gf256vAdd(matl2, 0, matl2F3, 0, static_cast<size_t>(Params.O2) * Params.O2);
		succ = RNBWGfMath::Gf256MatInv(matl2, matl2, Params.O2, matbuffer);
		// solve l2 eqs
		RNBWGfMath::Gf256MatProd(xo2, matl2, Params.O2, Params.O2, tempo, 0);
		++nattempt;
	};

	// w = T^-1 * y
	// identity part of T
	MemoryTools::Copy(vinegar, 0, w, 0, Params.V1);
	MemoryTools::Copy(xo1, 0, w, Params.V1, Params.O1);
	MemoryTools::Copy(xo2, 0, w, Params.V2, Params.O2);
	// Computing the T1 part
	RNBWGfMath::Gf256MatProd(y, Sk.T1, Params.V1, Params.O1, xo1, 0);
	RNBWGfMath::Gf256vAdd(w, 0, y, 0, Params.V1);
	// Computing the T4 part
	RNBWGfMath::Gf256MatProd(y, Sk.T4, Params.V1, Params.O2, xo2, 0);
	RNBWGfMath::Gf256vAdd(w, 0, y, 0, Params.V1);
	// Computing the T3 part
	RNBWGfMath::Gf256MatProd(y, Sk.T3, Params.O1, Params.O2, xo2, 0);
	RNBWGfMath::Gf256vAdd(w, Params.V1, y, 0, Params.O1);

	// return: copy w and salt to the Signature
	if (RAINBOW_MAX_ATTEMPT_FRMAT <= nattempt)
	{
		ret = -1;
	}
	else
	{
		RNBWGfMath::Gf256vAdd(Signature, SIGOFF, w, 0, Params.PubN);
		RNBWGfMath::Gf256vAdd(Signature, SIGOFF + Params.PubN, salt, 0, RAINBOW_SALT_BYTE);
	}

	return ret;
}

int32_t RNBWCore::RainbowVerifyClassic(RainbowParams &Params, const std::vector<byte> &Digest, const std::vector<byte> &Signature, const std::vector<byte> &Pk)
{
	std::vector<byte> digest_ck(Params.PubM);
	std::vector<byte> digestsalt(Params.HLen + RAINBOW_SALT_BYTE);
	std::vector<byte> tmpc(Params.PubM);
	size_t i;
	const size_t SIGOFF = Signature.size() - Params.SigLen;
	byte cc;

	cc = 0;

	// public_map( digest_ck , Pk , Signature ); Evaluating the quadratic public polynomials
	QuadTrimatEvalGf256(digest_ck, Pk, Signature, SIGOFF, Params.PubN, Params.PubM);
	MemoryTools::Copy(Digest, 0, digestsalt, 0, Params.HLen);
	MemoryTools::Copy(Signature, SIGOFF + Params.PubN, digestsalt, Params.HLen, RAINBOW_SALT_BYTE);

	// H( digest || salt )
	XOF(digestsalt, 0, digestsalt.size(), tmpc, 0, tmpc.size(), Params.Rate);

	// check consistancy
	for (i = 0; i < Params.PubM; ++i)
	{
		cc |= (digest_ck[i] ^ tmpc[i]);
	}

	return (0 == cc) ? 0 : -1;
}

void RNBWCore::RainbowGenerate(RainbowParams &Params, std::vector<byte> &publickey, std::vector<byte> &secretkey, std::unique_ptr<IPrng> &Rng)
{
	std::vector<byte> tmps(RAINBOW_LEN_SKSEED);

	Rng->Generate(tmps);
	GenerateKeyPair(Params, publickey, secretkey, tmps);
}

int32_t RNBWCore::RainbowSign(RainbowParams &Params, std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &Sk)
{
	std::vector<byte> tmpd(Params.HLen);
	int32_t ret;

	RainbowSecretKey tsk(Params);
	// hash the message using shake
	XOF(Message, 0, Message.size(), tmpd, 0, tmpd.size(), Params.Rate);
	// copy the message to the beginning of the signature
	MemoryTools::Copy(Message, 0, Signature, 0, Message.size());
	// return the size of the signature (not necessary?)
	tsk = RainbowSecretKey::Deserialize(Params, Sk);
	ret = RainbowSignClassic(Params, Signature, tsk, tmpd);

	return ret;
}

int32_t RNBWCore::RainbowVerify(RainbowParams &Params, std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &Pk)
{
	int32_t ret;

	if (Signature.size() >= Params.SigLen)
	{
		ret = 0;
	}
	else
	{
		ret = -1;
	}

	if (ret == 0)
	{
		std::vector<byte> tmpd(Params.HLen);
		MemoryTools::Copy(Signature, 0, Message, 0, Signature.size() - Params.SigLen);
		XOF(Message, 0, Message.size(), tmpd, 0, tmpd.size(), Params.Rate);
		ret = RainbowVerifyClassic(Params, tmpd, Signature, Pk);
	}

	return ret;
}

RNBWCore::RainbowParams RNBWCore::GetParams(RainbowParameters Parameters)
{
	RainbowParams params(Parameters);

	return params;
}

void RNBWCore::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
}

size_t RNBWCore::GetPublicKeySize(RainbowParameters Parameters)
{
	RainbowParams params(Parameters);

	return params.PubLen;
}

size_t RNBWCore::GetPrivateKeySize(RainbowParameters Parameters)
{
	RainbowParams params(Parameters);

	return params.PriLen;
}

size_t RNBWCore::GetSignatureSize(RainbowParameters Parameters)
{
	RainbowParams params(Parameters);

	return params.SigLen;
}

void RNBWCore::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, RainbowParameters Parameters)
{
	RainbowParams params = GetParams(Parameters);

	PublicKey.resize(params.PubLen);
	PrivateKey.resize(params.PriLen);

	RainbowGenerate(params, PublicKey, PrivateKey, Rng);
}

size_t RNBWCore::Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, RainbowParameters Parameters)
{
	RainbowParams params = GetParams(Parameters);

	Signature.resize(params.SigLen + Message.size());
	RainbowSign(params, Signature, Message, PrivateKey);

	return Signature.size();
}

bool RNBWCore::Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, RainbowParameters Parameters)
{
	RainbowParams params = GetParams(Parameters);
	int32_t ret;

	Message.resize(Signature.size() - params.SigLen);
	ret = RainbowVerify(params, Message, Signature, PublicKey);

	return static_cast<bool>(ret == 0);
}

NAMESPACE_RAINBOWEND
