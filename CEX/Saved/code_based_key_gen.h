#ifndef _CEX_CBKG_H
#define _CEX_CBKG_H

#include "CexDomain.h"
#include "IPrng.h"
#include "polyn_gf2m.h"
#include "MPKCKeyPair.h"
#include "MPKCPrivateKey.h"
#include "MPKCPublicKey.h"

NAMESPACE_MCELIECE

using Key::Asymmetric::MPKCKeyPair;
using Key::Asymmetric::MPKCPrivateKey;
using Key::Asymmetric::MPKCPublicKey;

/// <summary>
/// 
/// </summary>
class code_based_key_gen
{

	struct binary_matrix
	{
	public:

		void row_xor(uint32_t a, uint32_t b)
		{
			uint32_t i;
			for (i = 0; i<m_rwdcnt; i++)
			{
				m_elem[a*m_rwdcnt + i] ^= m_elem[b*m_rwdcnt + i];
			}
		}

		std::vector<int> row_reduced_echelon_form()
		{
			uint32_t i, failcnt, findrow, max = m_coln - 1;

			std::vector<int> perm(m_coln);
			for (i = 0; i<m_coln; i++)
			{
				perm[i] = i;//initialize permutation.
			}
			failcnt = 0;

			for (i = 0; i<m_rown; i++, max--)
			{
				findrow = 0;
				for (uint32_t j = i; j<m_rown; j++)
				{
					if (coef(j, max))
					{
						if (i != j)//not needed as ith row is 0 and jth row is 1.
							row_xor(i, j);//xor to the row.(swap)?
						findrow = 1;
						break;
					}//largest value found (end if)
				}

				if (!findrow)//if no row with a 1 found then swap last column and the column with no 1 down.
				{
					perm[m_coln - m_rown - 1 - failcnt] = max;
					failcnt++;
					if (!max)
					{
						//CSEC_FREE_MEM_CHK_SET_NULL(*p_perm);
						//CSEC_THR_RETURN();
						perm.resize(0);
					}
					i--;
				}
				else
				{
					perm[i + m_coln - m_rown] = max;
					for (uint32_t j = i + 1; j<m_rown; j++)//fill the column downwards with 0's
					{
						if (coef(j, (max)))
						{
							row_xor(j, i);//check the arg. order.
						}
					}

					for (int j = i - 1; j >= 0; j--)//fill the column with 0's upwards too.
					{
						if (coef(j, (max)))
						{
							row_xor(j, i);
						}
					}
				}
			}//end for(i)
			return perm;
		}


		binary_matrix(uint32_t rown, uint32_t coln)
		{
			m_coln = coln;
			m_rown = rown;
			m_rwdcnt = 1 + ((m_coln - 1) / 32);
			m_elem = std::vector<uint32_t>(m_rown * m_rwdcnt);
		}

		/**
		* return the coefficient out of F_2
		*/
		uint32_t coef(uint32_t i, uint32_t j)
		{
			return (m_elem[(i)* m_rwdcnt + (j) / 32] >> (j % 32)) & 1;
		}

		void set_coef_to_one(uint32_t i, uint32_t j)
		{
			m_elem[(i)* m_rwdcnt + (j) / 32] |= (static_cast<uint32_t>(1) << ((j) % 32));
		}

		void toggle_coeff(uint32_t i, uint32_t j)
		{
			m_elem[(i)* m_rwdcnt + (j) / 32] ^= (static_cast<uint32_t>(1) << ((j) % 32));
		}

		//private:
		uint32_t m_rown;  // number of rows.
		uint32_t m_coln; // number of columns.
		uint32_t m_rwdcnt; // number of words in a row
		std::vector<uint32_t> m_elem;
	};

	//the matrix is reduced from LSB...(from right)
	void randomize_support(std::vector<gf2m>& L, Prng::IPrng* rng)
	{
		for (uint32_t i = 0; i != L.size(); ++i)
		{
			gf2m rnd = polyn_gf2m::random_gf2m(rng);

			// no rejection sampling, but for useful code-based parameters with n <= 13 this seem tolerable
			std::swap(L[i], L[rnd % L.size()]);
		}
	}

	binary_matrix* generate_R(std::vector<gf2m> &L, polyn_gf2m* g, GF2m_Field* sp_field, uint32_t code_length, uint32_t t)
	{
		//L- Support
		//t- Number of errors
		//n- Length of the Goppa code
		//m- The extension degree of the GF
		//g- The generator polynomial.
		gf2m x, y;
		uint32_t i, j, k, r, n;
		std::vector<int> Laux(code_length);
		n = code_length;
		r = t*sp_field->get_extension_degree();

		binary_matrix H(r, n);

		for (i = 0; i < n; i++)
		{
			x = g->eval(gf2m_small_m::lex_to_gray(L[i]));//evaluate the polynomial at the point L[i].
			x = sp_field->gf_inv(x);
			y = x;
			for (j = 0; j < t; j++)
			{
				for (k = 0; k < sp_field->get_extension_degree(); k++)
				{
					if (y & (1 << k))
					{
						//the co-eff. are set in 2^0,...,2^11 ; 2^0,...,2^11 format along the rows/cols?
						H.set_coef_to_one(j*sp_field->get_extension_degree() + k, i);
					}
				}
				y = sp_field->gf_mul(y, gf2m_small_m::lex_to_gray(L[i]));
			}
		}//The H matrix is fed.

		std::vector<int> perm = H.row_reduced_echelon_form();
		if (perm.size() == 0)
		{
			// result still is NULL
			//throw Invalid_State("could not bring matrix in row reduced echelon form");
		}

		binary_matrix* result(new binary_matrix(n - r, r));
		for (i = 0; i < (*result).m_rown; ++i)
		{
			for (j = 0; j < (*result).m_coln; ++j)
			{
				if (H.coef(j, perm[i]))
				{
					result->toggle_coeff(i, j);
				}
			}
		}
		for (i = 0; i < code_length; ++i)
		{
			Laux[i] = L[perm[i]];
		}
		for (i = 0; i < code_length; ++i)
		{
			L[i] = Laux[i];
		}
		return result;
	}

	MPKCKeyPair* generate_mceliece_key(Prng::IPrng* rng, uint32_t ext_deg, uint32_t code_length, uint32_t t)
	{
		uint32_t i, j, k, l;
		binary_matrix* R;

		uint32_t codimension = t * ext_deg;
		if (code_length <= codimension)
		{
			//throw Invalid_Argument("invalid McEliece parameters");
		}
		GF2m_Field* sp_field = new GF2m_Field(ext_deg);

		//pick the support.........
		std::vector<gf2m> L(code_length);

		for (i = 0; i<code_length; i++)
		{
			L[i] = i;
		}
		randomize_support(L, rng);
		polyn_gf2m g(sp_field); // create as zero
		bool success = false;
		do
		{
			// create a random irreducible polynomial
			g = polyn_gf2m(t, rng, sp_field);

			try {
				R = generate_R(L, &g, sp_field, code_length, t);
				success = true;
			}
			catch (const bool &)
			{
			}
		} while (!success);

		std::vector<polyn_gf2m> sqrtmod = polyn_gf2m::sqrt_mod_init(g);
		std::vector<polyn_gf2m> F = polyn_gf2m::syndrome_init(g, L, code_length);

		// Each F[i] is the (precomputed) syndrome of the error vector with
		// a single '1' in i-th position.
		// We do not store the F[i] as polynomials of degree t , but
		// as binary vectors of length ext_deg * t (this will
		// speed up the syndrome computation)
		//
		//
		std::vector<uint32_t> H(gf2m_small_m::bit_size_to_32bit_size(codimension) * code_length);
		uint32_t* sk = H.data();
		for (i = 0; i < code_length; ++i)
		{
			for (l = 0; l < t; ++l)
			{
				k = (l * ext_deg) / 32;
				j = (l * ext_deg) % 32;
				sk[k] ^= static_cast<uint32_t>(F[i].get_coef(l)) << j;
				if (j + ext_deg > 32)
				{
					sk[k + 1] ^= F[i].get_coef(l) >> (32 - j);
				}
			}
			sk += gf2m_small_m::bit_size_to_32bit_size(codimension);
		}

		// We need the support L for decoding (decryption). In fact the
		// inverse is needed

		std::vector<gf2m> Linv(code_length);
		for (i = 0; i < code_length; ++i)
		{
			Linv[L[i]] = i;
		}
		std::vector<uint8_t> pubmat(R->m_elem.size() * 4);
		for (i = 0; i < R->m_elem.size(); i++)
		{
			store_le(R->m_elem[i], &pubmat[i * 4]);
		}

		MPKCPrivateKey* priKey =  new MPKCPrivateKey(g, H, sqrtmod, Linv, t, code_length);
		MPKCPublicKey* pubKey = new MPKCPublicKey(pubmat, g.get_degree(), Linv.size());

		return new MPKCKeyPair(priKey, pubKey);

		//return McEliece_PrivateKey(g, H, sqrtmod, Linv, pubmat);
	}

	template<typename T> inline uint8_t get_byte(size_t byte_num, T input)
	{
		return static_cast<uint8_t>(
			input >> (((~byte_num)&(sizeof(T) - 1)) << 3)
			);
	}

	/**
	* Store a little-endian uint32_t
	* @param in the input uint32_t
	* @param out the byte array to write to
	*/
	inline void store_le(uint32_t in, uint8_t out[4])
	{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
		uint32_t o = BOTAN_ENDIAN_L2N(in);
		std::memcpy(out, &o, sizeof(o));
#else
		out[0] = get_byte(3, in);
		out[1] = get_byte(2, in);
		out[2] = get_byte(1, in);
		out[3] = get_byte(0, in);
#endif
	}

};

NAMESPACE_MCELIECEEND
#endif