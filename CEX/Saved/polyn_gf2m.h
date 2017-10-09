#ifndef _CEX_GF2M_H
#define _CEX_GF2M_H

#include "CexDomain.h"
#include "IDigest.h"
#include "IPrng.h"
#include "GF2m_Field.h"

NAMESPACE_MCELIECE

/// <summary>
/// 
/// </summary>
struct polyn_gf2m
{
public:

	gf2m generate_gf2m_mask(gf2m a);
	unsigned nlz_16bit(uint16_t x);
	static gf2m random_gf2m(Prng::IPrng* rng);
	gf2m random_code_element(unsigned code_length, Prng::IPrng* rng);
	static gf2m eval_aux(const gf2m * /*restrict*/ coeff, gf2m a, int d, GF2m_Field* sp_field);
	static std::vector<polyn_gf2m> syndrome_init(polyn_gf2m const& generator, std::vector<gf2m> const& support, int n);

	/**
	* create a zero polynomial:
	*/
	explicit polyn_gf2m(GF2m_Field* sp_field);

	polyn_gf2m()
		:m_deg(-1) {}

	polyn_gf2m(const std::vector<uint8_t>& encoded, GF2m_Field* sp_field);

	polyn_gf2m& operator=(const polyn_gf2m&) = default;

	bool operator==(const polyn_gf2m & other) const;

	bool operator!=(const polyn_gf2m & other) const { return !(*this == other); }

	polyn_gf2m(polyn_gf2m&& other)
	{
		this->swap(other);
	}

	polyn_gf2m & operator=(polyn_gf2m&& other)
	{
		if (this != &other)
		{
			this->swap(other);
		}
		return *this;
	}

	void swap(polyn_gf2m& other);

	std::vector<uint8_t> encode() const;

	/**
	* create zero polynomial with reservation of space for a degree d polynomial
	*/
	polyn_gf2m(int d, GF2m_Field* sp_field);

	polyn_gf2m(polyn_gf2m const& other);
	/**
	* create zero polynomial with allocated size determined by specified degree d:
	*/

	/**
	* random irreducible polynomial of degree t
	*/
	polyn_gf2m(int t, Prng::IPrng* rng, GF2m_Field* sp_field);

	GF2m_Field* get_sp_field() const
	{
		return msp_field;
	}

	gf2m& operator[](size_t i) { return coeff[i]; }

	gf2m operator[](size_t i) const { return coeff[i]; }

	gf2m get_lead_coef() const { return coeff[m_deg]; }

	gf2m get_coef(uint32_t i) const { return coeff[i]; }

	inline void set_coef(uint32_t i, gf2m v)
	{
		coeff[i] = v;
	}

	inline void add_to_coef(uint32_t i, gf2m v)
	{
		coeff[i] = coeff[i] ^ v;
	}

	std::string to_string() const;

	/** decode a polynomial from memory: **/
	polyn_gf2m(const uint8_t* mem, uint32_t mem_len, GF2m_Field* sp_field);

	// remove one! ^v!
	/**
	*  create a polynomial from memory area (encoded)
	*/
	polyn_gf2m(int degree, const unsigned  char* mem, uint32_t mem_byte_len, GF2m_Field* sp_field);

	void encode(uint32_t min_numo_coeffs, uint8_t* mem, uint32_t mem_len) const;

	int get_degree() const;

	/**
	* determine the degree in a timing secure manner. the timing of this function
	* only depends on the number of allocated coefficients, not on the actual
	* degree
	*/
	int calc_degree_secure() const;

	void degppf(const polyn_gf2m & g, int* p_result);

	static std::vector<polyn_gf2m> sqmod_init(const polyn_gf2m & g);

	static std::vector<polyn_gf2m> sqrt_mod_init(const polyn_gf2m & g);


	polyn_gf2m sqmod(const std::vector<polyn_gf2m> & sq, int d);
	void set_to_zero();
	gf2m eval(gf2m a);

	static std::pair<polyn_gf2m, polyn_gf2m> eea_with_coefficients(const polyn_gf2m & p, const polyn_gf2m & g, int break_deg);

	void patchup_deg_secure(uint32_t trgt_deg, volatile gf2m patch_elem);

private:

	void set_degree(int d) { m_deg = d; }
	void poly_shiftmod(const polyn_gf2m & g);
	void realloc(uint32_t new_size);
	static polyn_gf2m gcd(polyn_gf2m const& p1, polyn_gf2m const& p2);

	/**
	* destructive:
	*/
	static void remainder(polyn_gf2m & p, const polyn_gf2m & g);

	static polyn_gf2m gcd_aux(polyn_gf2m& p1, polyn_gf2m& p2);

public:

	// public member variable:
	int m_deg;

	// public member variable:
	std::vector<gf2m> coeff;

	// public member variable:
	GF2m_Field* msp_field;
};

NAMESPACE_MCELIECEEND
#endif
