#ifndef _CEX_BITOPS_H
#define _CEX_BITOPS_H

#include "CexDomain.h"
#include "polyn_gf2m.h"
#include "gf2m_rootfind_dcmp.h"
#include "gf2m_small_m.h"
#include "MPKCPrivateKey.h"

NAMESPACE_MCELIECE

using Key::Asymmetric::MPKCPrivateKey;

class bit_ops
{
public:

	void matrix_arr_mul(std::vector<uint32_t> matrix, uint32_t numo_rows, uint32_t words_per_row, const uint8_t* input_vec, uint32_t* output_vec, uint32_t output_vec_len)
	{
		for (size_t j = 0; j < numo_rows; j++)
		{
			if ((input_vec[j / 8] >> (j % 8)) & 1)
			{
				for (size_t i = 0; i < output_vec_len; i++)
				{
					output_vec[i] ^= matrix[j * (words_per_row)+i];
				}
			}
		}
	}

	/**
	* returns the error vector to the syndrome
	*/
	std::vector<gf2m> goppa_decode(const polyn_gf2m & syndrom_polyn, const polyn_gf2m & g, const std::vector<polyn_gf2m> & sqrtmod, const std::vector<gf2m> & Linv)
	{
		gf2m a;
		uint32_t code_length = Linv.size();
		uint32_t t = g.get_degree();

		GF2m_Field* sp_field = g.get_sp_field();

		std::pair<polyn_gf2m, polyn_gf2m> h__aux = polyn_gf2m::eea_with_coefficients(syndrom_polyn, g, 1);
		polyn_gf2m & h = h__aux.first;
		polyn_gf2m & aux = h__aux.second;
		a = sp_field->gf_inv(aux.get_coef(0));
		gf2m log_a = sp_field->gf_log(a);
		for (int i = 0; i <= h.get_degree(); ++i)
		{
			h.set_coef(i, sp_field->gf_mul_zrz(log_a, h.get_coef(i)));
		}

		//  compute h(z) += z
		h.add_to_coef(1, 1);
		// compute S square root of h (using sqrtmod)
		polyn_gf2m S(t - 1, g.get_sp_field());

		for (uint32_t i = 0; i<t; i++)
		{
			a = sp_field->gf_sqrt(h.get_coef(i));

			if (i & 1)
			{
				for (uint32_t j = 0; j<t; j++)
				{
					S.add_to_coef(j, sp_field->gf_mul(a, sqrtmod[i / 2].get_coef(j)));
				}
			}
			else
			{
				S.add_to_coef(i / 2, a);
			}
		} /* end for loop (i) */


		S.get_degree();

		std::pair<polyn_gf2m, polyn_gf2m> v__u = polyn_gf2m::eea_with_coefficients(S, g, t / 2 + 1);
		polyn_gf2m & u = v__u.second;
		polyn_gf2m & v = v__u.first;

		// sigma = u^2+z*v^2
		polyn_gf2m sigma(t, g.get_sp_field());

		const size_t u_deg = u.get_degree();
		for (size_t i = 0; i <= u_deg; ++i)
		{
			sigma.set_coef(2 * i, sp_field->gf_square(u.get_coef(i)));
		}

		const int v_deg = v.get_degree();
		//BOTAN_ASSERT(v_deg > 0, "Valid degree");
		for (int i = 0; i <= v_deg; ++i)
		{
			sigma.set_coef(2 * i + 1, sp_field->gf_square(v.get_coef(i)));
		}

		std::vector<gf2m> res = gf2m_rootfind_dcmp::find_roots_gf2m_decomp(sigma, code_length);
		size_t d = res.size();

		std::vector<gf2m> result(d);
		for (uint32_t i = 0; i < d; ++i)
		{
			gf2m current = res[i];

			gf2m tmp;
			tmp = gf2m_small_m::gray_to_lex(current);
			if (tmp >= code_length) /* invalid root */
			{
				result[i] = i;
			}
			result[i] = Linv[tmp];
		}

		return result;
	}

	void mceliece_decrypt(std::vector<uint8_t>& plaintext_out, std::vector<uint8_t>& error_mask_out, const std::vector<uint8_t>& ciphertext, MPKCPrivateKey* key)
	{
		mceliece_decrypt(plaintext_out, error_mask_out, ciphertext.data(), ciphertext.size(), key);
	}

	void mceliece_decrypt(std::vector<uint8_t>& plaintext, std::vector<uint8_t> & error_mask, const uint8_t ciphertext[], size_t ciphertext_len, MPKCPrivateKey* key)
	{
		std::vector<gf2m> error_pos;
		plaintext = mceliece_decrypt(error_pos, ciphertext, ciphertext_len, key);

		const size_t code_length = key->get_code_length(); // get_code_length
		std::vector<uint8_t> result((code_length + 7) / 8);
		for (auto&& pos : error_pos)
		{
			if (pos > code_length)
			{
				throw;// Invalid_Argument("error position larger than code size");
			}
			result[pos / 8] |= (1 << (pos % 8));
		}

		error_mask = result;
	}

	/**
	* @p p_err_pos_len must point to the available length of @p error_pos on input, the
	* function will set it to the actual number of errors returned in the @p error_pos
	* array */
	std::vector<uint8_t> mceliece_decrypt(std::vector<gf2m> & error_pos, const uint8_t *ciphertext, uint32_t ciphertext_len, MPKCPrivateKey* key)
	{

		uint32_t dimension = key->get_dimension();
		uint32_t codimension = key->get_codimension();
		uint32_t t = key->G().get_degree();
		polyn_gf2m syndrome_polyn(key->G().get_sp_field()); // init as zero polyn
		const unsigned unused_pt_bits = dimension % 8;
		const uint8_t unused_pt_bits_mask = (1 << unused_pt_bits) - 1;

		if (ciphertext_len != (key->get_code_length() + 7) / 8)
		{
			throw;// Invalid_Argument("wrong size of McEliece ciphertext");
		}
		uint32_t cleartext_len = (key->get_message_word_bit_length() + 7) / 8;

		if (cleartext_len != gf2m_small_m::bit_size_to_byte_size(dimension))
		{
			throw;// Invalid_Argument("mce-decryption: wrong length of cleartext buffer");
		}

		std::vector<uint32_t> syndrome_vec(gf2m_small_m::bit_size_to_32bit_size(codimension));
		matrix_arr_mul(key->H(), key->get_code_length(), gf2m_small_m::bit_size_to_32bit_size(codimension), ciphertext, syndrome_vec.data(), syndrome_vec.size());

		std::vector<uint8_t> syndrome_byte_vec(gf2m_small_m::bit_size_to_byte_size(codimension));
		uint32_t syndrome_byte_vec_size = syndrome_byte_vec.size();
		for (uint32_t i = 0; i < syndrome_byte_vec_size; i++)
		{
			syndrome_byte_vec[i] = syndrome_vec[i / 4] >> (8 * (i % 4));
		}

		syndrome_polyn = polyn_gf2m(t - 1, syndrome_byte_vec.data(), gf2m_small_m::bit_size_to_byte_size(codimension), key->G().get_sp_field());
		syndrome_polyn.get_degree();
		error_pos = goppa_decode(syndrome_polyn, key->G(), key->SqrtMod(), key->LInv());
		uint32_t nb_err = error_pos.size();
		std::vector<uint8_t> cleartext(cleartext_len);
		memcpy(cleartext.data(), ciphertext, cleartext_len);

		for (uint32_t i = 0; i < nb_err; i++)
		{
			gf2m current = error_pos[i];

			if (current >= cleartext_len * 8)
			{
				// an invalid position, this shouldn't happen
				continue;
			}
			cleartext[current / 8] ^= (1 << (current % 8));
		}

		if (unused_pt_bits)
		{
			cleartext[cleartext_len - 1] &= unused_pt_bits_mask;
		}

		return cleartext;
	}
};

NAMESPACE_MCELIECEEND
#endif