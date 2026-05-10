/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/ber_dec.h>
   #include <botan/der_enc.h>
   #include <botan/pkix_types.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)
class X509_Alt_Name_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X509 AlternativeName tests");

         const std::vector<std::string> uri_names = {
            "https://example.com", "https://example.org", "https://sub.example.net"};

         const std::vector<std::string> dns_names = {
            "dns1.example.com",
            "dns2.example.org",
         };

         const std::vector<std::string> email_names = {
            "test@example.org",
            "admin@example.com",
            "root@example.net",
         };

         const std::vector<uint32_t> ipv4_names = {
            0xC0A80101,
            0xC0A80102,
         };

         const std::vector<Botan::IPv6Address> ipv6_names = {
            Botan::IPv6Address({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
            Botan::IPv6Address({0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
         };

         Botan::AlternativeName alt_name;
         for(const auto& uri : uri_names) {
            alt_name.add_uri(uri);
         }
         for(const auto& dns : dns_names) {
            alt_name.add_dns(dns);
         }
         for(const auto ipv4 : ipv4_names) {
            alt_name.add_ipv4_address(ipv4);
         }
         for(const auto& ipv6 : ipv6_names) {
            alt_name.add_ipv6_address(ipv6);
         }
         for(const auto& email : email_names) {
            alt_name.add_email(email);
         }

         alt_name.add_other_name(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10000, 1}, Botan::ASN1_String("foof"));
         alt_name.add_other_name(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10000, 2}, Botan::ASN1_String("yow"));

         // Raw OtherName whose inner value is a SEQUENCE (i.e. not an ASN1_String).
         const Botan::OID raw_other_oid{1, 3, 6, 1, 4, 1, 25258, 10000, 3};
         const std::vector<uint8_t> raw_other_value = {0x30, 0x03, 0x02, 0x01, 0x2A};
         alt_name.add_other_name_value(raw_other_oid, raw_other_value);

         alt_name.add_registered_id(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10001, 1});
         alt_name.add_registered_id(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10001, 2});

         Botan::X509_DN bonus_dn1;
         bonus_dn1.add_attribute("X520.CommonName", "cn1");
         alt_name.add_dn(bonus_dn1);

         Botan::X509_DN bonus_dn2;
         bonus_dn2.add_attribute("X520.CommonName", "cn2");
         alt_name.add_dn(bonus_dn2);

         std::vector<uint8_t> der;
         Botan::DER_Encoder enc(der);
         enc.encode(alt_name);

         Botan::AlternativeName recoded;
         Botan::BER_Decoder dec(der);
         dec.decode(recoded);

         result.test_sz_eq("Expected number of domains", recoded.dns().size(), dns_names.size());
         for(const auto& name : dns_names) {
            result.test_is_true("Has expected DNS name", recoded.dns().contains(name));
         }

         result.test_sz_eq("Expected number of URIs", recoded.uris().size(), uri_names.size());
         for(const auto& name : uri_names) {
            result.test_is_true("Has expected URI name", recoded.uris().contains(name));
         }

         result.test_sz_eq("Expected number of email", recoded.email().size(), email_names.size());
         for(const auto& name : email_names) {
            result.test_is_true("Has expected email name", recoded.email().contains(name));
         }

         result.test_sz_eq("Expected number of IPv4", recoded.ipv4_address().size(), ipv4_names.size());
         for(const auto ipv4 : ipv4_names) {
            result.test_is_true("Has expected IPv4 name", recoded.ipv4_address().contains(ipv4));
         }

         result.test_sz_eq("Expected number of IPv6", recoded.ipv6_address().size(), ipv6_names.size());
         for(const auto& ipv6 : ipv6_names) {
            result.test_is_true("Has expected IPv6 name", recoded.ipv6_address().contains(ipv6));
         }

         result.test_sz_eq("Expected number of DNs", recoded.directory_names().size(), 2);
         result.test_sz_eq("Expected number of Othernames", recoded.other_names().size(), 2);
         result.test_sz_eq("Expected number of OtherName values", recoded.other_name_values().size(), 3);
         result.test_sz_eq("Expected number of registeredIDs", recoded.registered_ids().size(), 2);

         // The raw-bytes OtherName roundtripped verbatim.
         const auto& on_set = recoded.other_name_values();
         auto raw_match = on_set.end();
         for(auto it = on_set.begin(); it != on_set.end(); ++it) {
            if(it->oid() == raw_other_oid) {
               raw_match = it;
               break;
            }
         }
         result.test_is_true("raw OtherName preserved", raw_match != on_set.end());
         if(raw_match != on_set.end()) {
            result.test_bin_eq("raw OtherName value bytes match", raw_match->value(), raw_other_value);
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_alt_name", X509_Alt_Name_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
