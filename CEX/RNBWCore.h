#ifndef CEX_RAINBOWCORE_H
#define CEX_RAINBOWCORE_H

#include "CexConfig.h"
#include "IPrng.h"
#include "RainbowParameters.h"


NAMESPACE_RAINBOW

using Prng::IPrng;
using Enumeration::RainbowParameters;

/// <summary>
/// The Rainbow support class
/// </summary>
class RNBWCore
{
private:

	static const size_t RAINBOW_LEN_SKSEED = 32;
	static const size_t RAINBOW_MAX_ATTEMPT_FRMAT = 128;
	static const size_t RAINBOW_SALT_BYTE = 16;
	static const size_t RAINBOW_SKSEED_SIZE = 32;

	class RainbowParams;
	class RainbowPublicKey;
	class RainbowSecretKey;

	static uint IdxOfTrimat(size_t Row, size_t Column, size_t Dimension);
	static uint IdxOf2Trimat(size_t Row, size_t Column, size_t N);
	static void UpperTrianglize(std::vector<byte> &Btric, const std::vector<byte> &Ba, size_t AWidth, size_t BatchSize);
	static void TrimatMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Btria, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize);
	static void TrimatTrMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Btria, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize);
	static void Trimat2MaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Btria, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize);
	static void MatTrMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &AtoTr, size_t AHeight, size_t AColVecSize, size_t AWidth, const std::vector<byte> &Bb, size_t BWidth, size_t BatchSize);
	static void BmatTrMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &BaToTr, size_t AwidthBeforeTr, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize);
	static void MatMaddGf256(std::vector<byte> &Bc, const std::vector<byte> &Ba, size_t AHeight, const std::vector<byte> &B, size_t BHeight, uint BColVecSize, size_t BWidth, size_t BatchSize);
	static void QuadTrimatEvalGf256(std::vector<byte> &Y, const std::vector<byte> &TriMat, const std::vector<byte> &X, size_t XOffset, size_t Dim, size_t BatchSize);
	static void QuadRecmatEvalGf256(std::vector<byte> &Z, const std::vector<byte> &Y, size_t DimY, const std::vector<byte> &Mat, const std::vector<byte> &X, size_t DimX, size_t BatchSize);
	static void GenerateST(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed);
	static void GenerateL1F12(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed);
	static void GenerateL2F12356(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed);
	static void GenerateB1B2(RainbowParams &Params, RainbowSecretKey &Sk, std::vector<byte> &Seed);
	static void CalculateT4(RainbowParams &Params, std::vector<byte> &T2toT4, const std::vector<byte> &T1, const std::vector<byte> &T3);
	static void ObsfucateL1Polys(RainbowParams &Params, std::vector<byte> &L1Polys, const std::vector<byte> &L2Polys, uint Terms, const std::vector<byte> &S1);
	static void GenerateSecretkeyHelper(RainbowParams &Params, RainbowSecretKey &Sk, const std::vector<byte> &SkSeed);
	static void GenerateKeyPair(RainbowParams &Params, std::vector<byte> &Pk, std::vector<byte> &Sk, const std::vector<byte> &SkSeed);
	static void ExtCpkToPk(RainbowParams &Params, std::vector<byte> &Pk, const RainbowPublicKey &CPk);
	static void CalculateQFromF(RainbowParams &Params, RainbowPublicKey &Qs, const RainbowSecretKey &Fs, const RainbowSecretKey &Ts);
	static void CalculateQfromF(RainbowParams &Params, RainbowPublicKey &Qs, const RainbowSecretKey &Fs, const RainbowSecretKey &Ts);
	static int32_t RainbowSignClassic(RainbowParams &Params, std::vector<byte> &Signature, const RainbowSecretKey &Sk, const std::vector<byte> &Digest);
	static int32_t RainbowVerifyClassic(RainbowParams &Params, const std::vector<byte> &Digest, const std::vector<byte> &Signature, const std::vector<byte> &Pk);
	static void RainbowGenerate(RainbowParams &Params, std::vector<byte> &publickey, std::vector<byte> &secretkey, std::unique_ptr<IPrng> &Rng);
	static int32_t RainbowSign(RainbowParams &Params, std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &Sk);
	static int32_t RainbowVerify(RainbowParams &Params, std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &Pk);

public:

	static RainbowParams GetParams(RainbowParameters Parameters);

	static size_t GetPublicKeySize(RainbowParameters Parameters);

	static size_t GetPrivateKeySize(RainbowParameters Parameters);

	static size_t GetSignatureSize(RainbowParameters Parameters);

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, RainbowParameters Parameters);

	static size_t Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, RainbowParameters Parameters);

	static bool Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, RainbowParameters Parameters);

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);
};

NAMESPACE_RAINBOWEND
#endif
