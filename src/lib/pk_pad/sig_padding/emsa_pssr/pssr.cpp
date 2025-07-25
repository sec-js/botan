/*
* PSSR
* (C) 1999-2007,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pssr.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/mgf1.h>
#include <array>

namespace Botan {

namespace {

/*
* PSSR Encode Operation
*/
std::vector<uint8_t> pss_encode(HashFunction& hash,
                                std::span<const uint8_t> msg,
                                std::span<const uint8_t> salt,
                                size_t output_bits) {
   const size_t HASH_SIZE = hash.output_length();

   if(msg.size() != HASH_SIZE) {
      throw Encoding_Error("Cannot encode PSS string, input length invalid for hash");
   }
   if(output_bits < 8 * HASH_SIZE + 8 * salt.size() + 9) {
      throw Encoding_Error("Cannot encode PSS string, output length too small");
   }

   const size_t output_length = ceil_tobytes(output_bits);
   const uint8_t db0_mask = 0xFF >> (8 * output_length - output_bits);

   std::array<uint8_t, 8> padding = {0};
   hash.update(padding);
   hash.update(msg);
   hash.update(salt);
   std::vector<uint8_t> H = hash.final_stdvec();

   const size_t db_len = output_length - HASH_SIZE - 1;
   std::vector<uint8_t> EM(output_length);

   BufferStuffer stuffer(EM);
   stuffer.append(0x00, stuffer.remaining_capacity() - (1 + salt.size() + H.size() + 1));
   stuffer.append(0x01);
   stuffer.append(salt);

   mgf1_mask(hash, H.data(), H.size(), EM.data(), db_len);
   EM[0] &= db0_mask;

   stuffer.append(H);
   stuffer.append(0xBC);
   BOTAN_ASSERT_NOMSG(stuffer.full());

   return EM;
}

bool pss_verify(HashFunction& hash,
                std::span<const uint8_t> pss_repr,
                std::span<const uint8_t> message_hash,
                size_t key_bits,
                size_t* out_salt_size) {
   const size_t HASH_SIZE = hash.output_length();
   const size_t key_bytes = ceil_tobytes(key_bits);

   if(key_bits < 8 * HASH_SIZE + 9) {
      return false;
   }

   if(message_hash.size() != HASH_SIZE) {
      return false;
   }

   if(pss_repr.size() > key_bytes || pss_repr.size() <= 1) {
      return false;
   }

   if(pss_repr[pss_repr.size() - 1] != 0xBC) {
      return false;
   }

   std::vector<uint8_t> coded;
   if(pss_repr.size() < key_bytes) {
      coded.resize(key_bytes);
      BufferStuffer stuffer(coded);
      stuffer.append(0x00, key_bytes - pss_repr.size());
      stuffer.append(pss_repr);
   } else {
      coded.assign(pss_repr.begin(), pss_repr.end());
   }

   // We have to check this after potential zero padding above
   const size_t top_bits = 8 * ((key_bits + 7) / 8) - key_bits;
   if(top_bits > 8 - high_bit(coded[0])) {
      return false;
   }

   uint8_t* DB = coded.data();
   const size_t DB_size = coded.size() - HASH_SIZE - 1;

   const uint8_t* H = &coded[DB_size];
   const size_t H_size = HASH_SIZE;

   mgf1_mask(hash, H, H_size, DB, DB_size);
   DB[0] &= 0xFF >> top_bits;

   size_t salt_offset = 0;
   for(size_t j = 0; j != DB_size; ++j) {
      if(DB[j] == 0x01) {
         salt_offset = j + 1;
         break;
      }
      if(DB[j] != 0x00) {
         return false;
      }
   }
   if(salt_offset == 0) {
      return false;
   }

   const size_t salt_size = DB_size - salt_offset;

   std::array<uint8_t, 8> padding = {0};
   hash.update(padding);
   hash.update(message_hash);
   hash.update(&DB[salt_offset], salt_size);

   const std::vector<uint8_t> H2 = hash.final_stdvec();

   const bool ok = CT::is_equal(H, H2.data(), HASH_SIZE).as_bool();

   if(ok && out_salt_size != nullptr) {
      *out_salt_size = salt_size;
   }

   return ok;
}

}  // namespace

PSSR::PSSR(std::unique_ptr<HashFunction> hash) :
      m_hash(std::move(hash)), m_salt_size(m_hash->output_length()), m_required_salt_len(false) {}

PSSR::PSSR(std::unique_ptr<HashFunction> hash, size_t salt_size) :
      m_hash(std::move(hash)), m_salt_size(salt_size), m_required_salt_len(true) {}

/*
* PSSR Update Operation
*/
void PSSR::update(const uint8_t input[], size_t length) {
   m_hash->update(input, length);
}

/*
* Return the raw (unencoded) data
*/
std::vector<uint8_t> PSSR::raw_data() {
   return m_hash->final_stdvec();
}

std::vector<uint8_t> PSSR::encoding_of(std::span<const uint8_t> msg, size_t output_bits, RandomNumberGenerator& rng) {
   const auto salt = rng.random_vec<std::vector<uint8_t>>(m_salt_size);
   return pss_encode(*m_hash, msg, salt, output_bits);
}

/*
* PSSR Decode/Verify Operation
*/
bool PSSR::verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) {
   size_t salt_size = 0;
   const bool ok = pss_verify(*m_hash, coded, raw, key_bits, &salt_size);

   if(m_required_salt_len && salt_size != m_salt_size) {
      return false;
   }

   return ok;
}

std::string PSSR::hash_function() const {
   return m_hash->name();
}

std::string PSSR::name() const {
   return fmt("PSS({},MGF1,{})", m_hash->name(), m_salt_size);
}

PSS_Raw::PSS_Raw(std::unique_ptr<HashFunction> hash) :
      m_hash(std::move(hash)), m_salt_size(m_hash->output_length()), m_required_salt_len(false) {}

PSS_Raw::PSS_Raw(std::unique_ptr<HashFunction> hash, size_t salt_size) :
      m_hash(std::move(hash)), m_salt_size(salt_size), m_required_salt_len(true) {}

/*
* PSS_Raw Update Operation
*/
void PSS_Raw::update(const uint8_t input[], size_t length) {
   m_msg.insert(m_msg.end(), input, input + length);
}

/*
* Return the raw (unencoded) data
*/
std::vector<uint8_t> PSS_Raw::raw_data() {
   std::vector<uint8_t> ret;
   std::swap(ret, m_msg);

   if(ret.size() != m_hash->output_length()) {
      throw Encoding_Error("PSS_Raw Bad input length, did not match hash");
   }

   return ret;
}

std::vector<uint8_t> PSS_Raw::encoding_of(std::span<const uint8_t> msg,
                                          size_t output_bits,
                                          RandomNumberGenerator& rng) {
   const auto salt = rng.random_vec<std::vector<uint8_t>>(m_salt_size);
   return pss_encode(*m_hash, msg, salt, output_bits);
}

/*
* PSS_Raw Decode/Verify Operation
*/
bool PSS_Raw::verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) {
   size_t salt_size = 0;
   const bool ok = pss_verify(*m_hash, coded, raw, key_bits, &salt_size);

   if(m_required_salt_len && salt_size != m_salt_size) {
      return false;
   }

   return ok;
}

std::string PSS_Raw::hash_function() const {
   return m_hash->name();
}

std::string PSS_Raw::name() const {
   return fmt("PSS_Raw({},MGF1,{})", m_hash->name(), m_salt_size);
}

}  // namespace Botan
