#include <fc/crypto/public_key.hpp>
#include <fc/crypto/common.hpp>
#include <fc/exception/exception.hpp>

namespace fc { namespace crypto {

   struct recovery_visitor : fc::visitor<public_key::storage_type> {
      recovery_visitor(const sha256& digest, bool check_canonical)
      :_digest(digest)
      ,_check_canonical(check_canonical)
      {}

      template<typename SignatureType>
      public_key::storage_type operator()(const SignatureType& s) const {
         return public_key::storage_type(s.recover(_digest, _check_canonical));
      }

      const sha256& _digest;
      bool _check_canonical;
   };

   public_key::public_key( const signature& c, const sha256& digest, bool check_canonical )
   :_storage(c._storage.visit(recovery_visitor(digest, check_canonical)))
   {
   }

   static public_key::storage_type parse_base58(const std::string& base58str)
   {
      bool has_no_delimiter = base58str.find('_') == std::string::npos;

      constexpr auto legacy_prefix_yosemite = config::public_key_legacy_prefix_yosemite;
      if( prefix_matches(legacy_prefix_yosemite, base58str) && has_no_delimiter) {

         auto sub_str = base58str.substr(config::public_key_first_prefix_size);
         using yosemite_pub_key_type = typename public_key::storage_type::template type_at<2>;
         using yosemite_pub_key_data_type = yosemite_pub_key_type::data_type;
         using wrapper = checksummed_data<yosemite_pub_key_data_type>;
         auto bin = fc::from_base58(sub_str);
         FC_ASSERT(bin.size() == sizeof(yosemite_pub_key_data_type) + sizeof(uint32_t), "");
         auto wrapped = fc::raw::unpack<wrapper>(bin);
         FC_ASSERT(wrapper::calculate_checksum(wrapped.data) == wrapped.check);
         return public_key::storage_type(yosemite_pub_key_type(wrapped.data));

      } else {

         constexpr auto legacy_prefix_eos = config::public_key_legacy_prefix_eos;
         if( prefix_matches(legacy_prefix_eos, base58str) && has_no_delimiter ) {
            auto sub_str = base58str.substr(config::public_key_first_prefix_size);
            using eos_pub_key_type = typename public_key::storage_type::template type_at<0>;
            using eos_pub_key_data_type = eos_pub_key_type::data_type;
            using wrapper = checksummed_data<eos_pub_key_data_type>;
            auto bin = fc::from_base58(sub_str);
            FC_ASSERT(bin.size() == sizeof(eos_pub_key_data_type) + sizeof(uint32_t), "");
            auto wrapped = fc::raw::unpack<wrapper>(bin);
            FC_ASSERT(wrapper::calculate_checksum(wrapped.data) == wrapped.check);
            return public_key::storage_type(eos_pub_key_type(wrapped.data));
         } else {
            constexpr auto prefix = config::public_key_base_prefix;

            const auto pivot = base58str.find('_');
            FC_ASSERT(pivot != std::string::npos, "No delimiter in string, cannot determine data type: ${str}", ("str", base58str));

            const auto prefix_str = base58str.substr(0, pivot);
            FC_ASSERT(prefix == prefix_str, "Public Key has invalid prefix: ${str}", ("str", base58str)("prefix_str", prefix_str));

            auto data_str = base58str.substr(pivot + 1);
            FC_ASSERT(!data_str.empty(), "Public Key has no data: ${str}", ("str", base58str));
            return base58_str_parser<public_key::storage_type, config::public_key_prefix>::apply(data_str);
         }
      }
   }

   public_key::public_key(const std::string& base58str)
   :_storage(parse_base58(base58str))
   {}

   struct is_valid_visitor : public fc::visitor<bool> {
      template< typename KeyType >
      bool operator()( const KeyType& key )const {
         return key.valid();
      }
   };

   bool public_key::valid()const
   {
      return _storage.visit(is_valid_visitor());
   }

   public_key::operator std::string() const
   {
      auto which = _storage.which();
      if (which == 2) {
         auto data_str = _storage.visit(base58str_visitor<storage_type, config::public_key_prefix, 2>());
         return std::string(config::public_key_legacy_prefix_yosemite) + data_str;
//      } else if (which == 0) {
//         auto data_str = _storage.visit(base58str_visitor<storage_type, config::public_key_prefix, 0>());
//         return std::string(config::public_key_legacy_prefix_eos) + data_str;
      } else {
         auto data_str = _storage.visit(base58str_visitor<storage_type, config::public_key_prefix>());
         return std::string(config::public_key_base_prefix) + "_" + data_str;
      }
   }

   std::ostream& operator<<(std::ostream& s, const public_key& k) {
      s << "public_key(" << std::string(k) << ')';
      return s;
   }

   bool operator == ( const public_key& p1, const public_key& p2) {
      return eq_comparator<public_key::storage_type>::apply(p1._storage, p2._storage);
   }

   bool operator != ( const public_key& p1, const public_key& p2) {
      return !(p1 == p2);
   }

   bool operator < ( const public_key& p1, const public_key& p2)
   {
      return less_comparator<public_key::storage_type>::apply(p1._storage, p2._storage);
   }
} } // fc::crypto

namespace fc
{
   using namespace std;
   void to_variant(const fc::crypto::public_key& var, fc::variant& vo)
   {
      vo = std::string(var);
   }

   void from_variant(const fc::variant& var, fc::crypto::public_key& vo)
   {
      vo = fc::crypto::public_key(var.as_string());
   }
} // fc
