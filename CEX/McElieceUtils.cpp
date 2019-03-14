#include "McElieceUtils.h"

NAMESPACE_MCELIECE

//~~~Public Functions~~~//

ushort McElieceUtils::Diff(ushort X, ushort Y)
{
	uint t = static_cast<uint>(X ^ Y);
	t = ((t - 1) >> 20) ^ 0xFFF;

	return static_cast<ushort>(t);
}

ushort McElieceUtils::Invert(ushort X, size_t Degree)
{
	ushort tmpA;
	ushort tmpB;
	ushort out = X;

	out = Square(out, Degree);
	tmpA = Multiply(out, X, Degree);
	out = Square(tmpA, Degree);
	out = Square(out, Degree);
	tmpB = Multiply(out, tmpA, Degree);
	out = Square(tmpB, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Multiply(out, tmpB, Degree);
	out = Square(out, Degree);
	out = Square(out, Degree);
	out = Multiply(out, tmpA, Degree);
	out = Square(out, Degree);
	out = Multiply(out, X, Degree);

	return Square(out, Degree);
}

ulong McElieceUtils::MaskNonZero64(ushort X)
{
	ulong ret = X;

	ret -= 1;
	ret >>= 63;
	ret -= 1;

	return ret;
}

ulong McElieceUtils::MaskLeq64(ushort X, ushort Y)
{
	ulong tmpA = X;
	ulong tmpB = Y;
	ulong ret = tmpB - tmpA;

	ret >>= 63;
	ret -= 1;

	return ret;
}

ushort McElieceUtils::Multiply(ushort X, ushort Y, size_t Degree)
{
	uint t;
	uint t0;
	uint t1;
	uint tmp;

	t0 = X;
	t1 = Y;
	tmp = t0 * (t1 & 1);

	for (size_t i = 1; i < Degree; i++)
	{
		tmp ^= (t0 * (t1 & (1 << i)));
	}

	t = tmp & 0x7FC000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	t = tmp & 0x3000;
	tmp ^= t >> 9;
	tmp ^= t >> 12;

	return tmp & ((1 << Degree) - 1);
}

ushort McElieceUtils::Square(ushort X, size_t Degree)
{
	static const std::array<uint, 4> B =
	{
		0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF
	};

	uint y = X;
	uint t;

	y = (y | (y << 8)) & B[3];
	y = (y | (y << 4)) & B[2];
	y = (y | (y << 2)) & B[1];
	y = (y | (y << 1)) & B[0];

	t = y & 0x7FC000;
	y ^= t >> 9;
	y ^= t >> 12;

	t = y & 0x3000;
	y ^= t >> 9;
	y ^= t >> 12;

	return y & ((1 << Degree) - 1);
}

NAMESPACE_MCELIECEEND
