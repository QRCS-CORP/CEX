#include "CexDomain.h"

NAMESPACE_ECDH

class EC25519
{
public:

	static const size_t EC25519_CURVE_SIZE = 32;
	static const size_t EC25519_PUBLICKEY_SIZE = 32;
	static const size_t EC25519_PRIVATEKEY_SIZE = 64;
	static const size_t EC25519_SECRET_SIZE = 32;
	static const size_t EC25519_SEED_SIZE = 32;
	static const size_t EC25519_SIGNATURE_SIZE = 64;

#if defined(CEX_SYSTEM_NATIVE_UINT128)
	typedef std::array<uint64_t, 5> fe25519;
#else
	typedef std::array<int32_t, 10> fe25519;
#endif

	typedef struct
	{
		fe25519 x;
		fe25519 y;
		fe25519 z;
	} ge25519p2;

	typedef struct
	{
		fe25519 x;
		fe25519 y;
		fe25519 z;
		fe25519 t;
	} ge25519p3;

	typedef struct
	{
		fe25519 x;
		fe25519 y;
		fe25519 z;
		fe25519 t;
	} ge25519p1p1;

	typedef struct
	{
		fe25519 yplusx;
		fe25519 yminusx;
		fe25519 xy2d;
	} ge25519precomp;

	typedef struct
	{
		fe25519 yplusx;
		fe25519 yminusx;
		fe25519 z;
		fe25519 t2d;
	} ge25519cached;

	static int32_t EcdsaBaseIsZero(const std::vector<uint8_t> &N, const size_t Nlen);
	static uint64_t EcdsaBaseLoad3(const std::vector<uint8_t> &Input, size_t Offset);
	static uint64_t EcdsaBaseLoad4(const std::vector<uint8_t> &Input, size_t Offset);
	static uint8_t EcdsaBaseNegative(int8_t B);
	static void EcdsaBaseSlideVarTime(std::vector<int8_t> &R, const std::vector<uint8_t> &A, size_t AOffset);

#if defined(CEX_SYSTEM_NATIVE_UINT128)

	static const int64_t Ed25519A32 = 486662;
	static const fe25519 Fe25519SqrtM1;
	static const fe25519 Ed25519SqrtaM2;
	static const fe25519 Ed25519D;
	static const fe25519 Ed25519D2;
	static const fe25519 Ed25519A;
	static const fe25519 Ed25519SqrtadM1;
	static const fe25519 Ed25519InvSqrtaMd;
	static const fe25519 Ed25519OneMsQd;
	static const fe25519 Ed25519SqdMOne;

	static void Fe25519Zero(fe25519 &H);
	static void Fe25519One(fe25519 &H);
	static void Fe25519Add(fe25519 &H, const fe25519 &F, const fe25519 &G);
	static void Fe25519Sub(fe25519 &H, const fe25519 &F, const fe25519 &G);
	static void Fe25519Neg(fe25519 &H, const fe25519 &F);
	static void Fe25519cMov(fe25519 &F, const fe25519 &G, uint32_t B);
	static void Fe25519cSwap(fe25519 &F, fe25519 &G, uint32_t B);
	static void Fe25519Copy(fe25519 &H, const fe25519 &F);
	static int32_t Fe25519IsNegative(const fe25519 &F);
	static int32_t Fe25519IsZero(const fe25519 &F);
	static void Fe25519Mul(fe25519 &H, const fe25519 &F, const fe25519 &G);
	static void Fe25519Sq(fe25519 &H, const fe25519 &F);
	static void Fe25519Sq2(fe25519 &H, const fe25519 &F);
	static void Fe25519Mul32(fe25519 &H, const fe25519 &F, uint32_t N);
	static void Fe25519FromBytes(fe25519 &H, const std::vector<uint8_t> &S);
	static void Fe25519Reduce(fe25519 &H, const fe25519 &F);
	static void Fe25519ToBytes(std::vector<uint8_t> &S, const fe25519 &H);

#else

	static const fe25519 Ed25519D;
	static const fe25519 Ed25519D2;
	static const fe25519 Fe25519SqrtM1;

	static void Fe25519Zero(fe25519 &H);
	static void Fe25519One(fe25519 &H);
	static void Fe25519Add(fe25519 &H, const fe25519 &F, const fe25519 &G);
	static void Fe25519cSwap(fe25519 &F, fe25519 &G, uint32_t B);
	static void Fe25519Sub(fe25519 &H, const fe25519 &F, const fe25519 &G);
	static void Fe25519Neg(fe25519 &H, const fe25519 &F);
	static void Fe25519cMov(fe25519 &F, const fe25519 &G, uint32_t B);
	static void Fe25519Copy(fe25519 &H, const fe25519 &F);
	static int32_t Fe25519IsNegative(const fe25519 &F);
	static int32_t Fe25519IsZero(const fe25519 &F);
	static void Fe25519Mul(fe25519 &H, const fe25519 &F, const fe25519 &G);
	static void Fe25519Mul32(fe25519 &H, const fe25519 &F, uint32_t N);
	static void Fe25519Sq(fe25519 &H, const fe25519 &F);
	static void Fe25519Sq2(fe25519 &H, const fe25519 &F);
	static void Fe25519FromBytes(fe25519 &H, const std::vector<uint8_t> &S);
	static void Fe25519Reduce(fe25519 &H, const fe25519 &F);
	static void Fe25519ToBytes(std::vector<uint8_t> &S, const fe25519 &H);

#endif

	static void Fe25519Pow22523(fe25519 &Output, const fe25519 &Z);
	static void Fe25519Invert(fe25519 &Output, const fe25519 &Z);
	static void Fe25519AddPrecomp(ge25519p1p1 &R, const ge25519p3 &P, const ge25519precomp &Q);
	
	static void Ge25519P3Zero(ge25519p3 &H);
	static void Ge25519PrecompZero(ge25519precomp &H);
	static void Ge25519cMov(ge25519precomp &T, const ge25519precomp &U, uint8_t B);
	static uint8_t Ge25519Equal(int8_t B, int8_t C);
	static void Ge25519cMov8(ge25519precomp &T, const std::vector<ge25519precomp> &PreComp, const int8_t B);
	static void Ge25519cMov8Base(ge25519precomp &T, const int32_t Position, const int8_t B);
	static void Ge25519P2Dbl(ge25519p1p1 &R, const ge25519p2 &P);
	static void Ge25519P3ToP2(ge25519p2 &R, const ge25519p3 &P);
	static void Ge25519P3Dbl(ge25519p1p1 &R, const ge25519p3 &P);
	static void Ge25519P2Zero(ge25519p2 &H);
	static void Ge25519P1P1ToP3(ge25519p3 &R, const ge25519p1p1 &P);
	static void Ge25519P1P1ToP2(ge25519p2 &R, const ge25519p1p1 &P);
	static void Ge25519ScalarBase(ge25519p3 &H, const std::vector<uint8_t> &A);
	static void Ge25519P3ToBytes(std::vector<uint8_t> &S, const ge25519p3 &H);
	static int32_t Ge25519IsCanonical(const std::vector<uint8_t> &S);
	static int32_t Ge25519HasSmallOrder(const std::vector<uint8_t> &S);
	static int32_t Ge25519FromBytesNegateVarTime(ge25519p3 &H, const std::vector<uint8_t> &S);
	static void Ge25519P3ToCached(ge25519cached &R, const ge25519p3 &P);
	static void Ge25519AddCached(ge25519p1p1 &R, const ge25519p3 &P, const ge25519cached &Q);
	static void Ge25519SubPrecomp(ge25519p1p1 &R, const ge25519p3 &P, const ge25519precomp &Q);
	static void Ge25519DoubleScalarMultVarTime(ge25519p2 &R, const std::vector<uint8_t> &A, const ge25519p3 &AL, const std::vector<uint8_t> &B, size_t BOffset);
	static void Ge25519SubCached(ge25519p1p1 &R, const ge25519p3 &P, const ge25519cached &Q);
	static void Ge25519ToBytes(std::vector<uint8_t> &S, const ge25519p2 &H);

	static void EdwardsToMontgomery(fe25519 &MontgomeryX, const fe25519 &EdwardsY, const fe25519 &EdwardsZ);
	static int32_t ScalarmultCurve25519Ref10Base(std::vector<uint8_t> &Q, const std::vector<uint8_t> &N);
	static int32_t ScalarMultCurve25519Ref10(std::vector<uint8_t> &Q, const std::vector<uint8_t> &N, const std::vector<uint8_t> &P);
	static int32_t ScalarMultCurve25519(std::vector<uint8_t> &Q, const std::vector<uint8_t> &N, const std::vector<uint8_t> &P);

	static int32_t Ed25519SmallOrder(const std::vector<uint8_t> &S);
	static void Sc25519Clamp(std::vector<uint8_t> &K);
	static int32_t Sc25519IsCanonical(const std::vector<uint8_t> &S, size_t Offset);
	static void Sc25519MulAdd(std::vector<uint8_t> &S, size_t SOffset, const std::vector<uint8_t> &A, const std::vector<uint8_t> &B, const std::vector<uint8_t> &C);
	static void Sc25519Reduce(std::vector<uint8_t> &S);
	static int32_t Sc25519Verify(const std::vector<uint8_t> &X, const std::vector<uint8_t> &Y, const size_t N);
};

NAMESPACE_ECDHEND
