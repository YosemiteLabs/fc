#include <fc/crypto/signature.hpp>
#include <fc/crypto/common.hpp>
#include <fc/exception/exception.hpp>

namespace fc { namespace crypto {
   struct hash_visitor : public fc::visitor<size_t> {
      template<typename SigType>
      size_t operator()(const SigType& sig) const {
         static_assert(sizeof(sig._data.data) == 65, "sig size is expected to be 65");
         //signatures are two bignums: r & s. Just add up least significant digits of the two
         return *(size_t*)&sig._data.data[32-sizeof(size_t)] + *(size_t*)&sig._data.data[64-sizeof(size_t)];
      }
   };

   static signature::storage_type parse_base58(const std::string& base58str)
   {
      constexpr auto legacy_prefix_yosemite = config::signature_legacy_prefix_yosemite;

      const auto pivot = base58str.find('_');
      FC_ASSERT(pivot != std::string::npos, "No delimiter in string, cannot determine type: ${str}", ("str", base58str));

      const auto prefix_str = base58str.substr(0, pivot);

      if (prefix_str == legacy_prefix_yosemite) {

         using yosemite_sig_type = signature::storage_type::template type_at<2>;
         using yosemite_sig_data_type = typename yosemite_sig_type::data_type;
         using wrapper = checksummed_data<yosemite_sig_data_type>;

         auto curve_type_sig_str = base58str.substr(pivot + 1);

         const auto pivot_curve_type = curve_type_sig_str.find('_');
         FC_ASSERT(pivot_curve_type != std::string::npos, "No delimiter in data, cannot determine suite type: ${str}", ("str", base58str));

         auto prefix_k1 = config::signature_prefix[1];
         const auto curve_type_prefix_str = curve_type_sig_str.substr(0, pivot_curve_type);
         FC_ASSERT(curve_type_prefix_str == prefix_k1, "secp256k1 curve should be usded for yosemite signature storage type");

         auto sig_data_str = curve_type_sig_str.substr(pivot_curve_type + 1);
         FC_ASSERT(!sig_data_str.empty(), "empty signature data");

         auto bin = fc::from_base58(sig_data_str);
         FC_ASSERT(bin.size() >= sizeof(yosemite_sig_data_type) + sizeof(uint32_t));
         auto wrapped = fc::raw::unpack<wrapper>(bin);
         auto checksum = wrapper::calculate_checksum(wrapped.data, prefix_k1);
         FC_ASSERT(checksum == wrapped.check);
         return signature::storage_type(yosemite_sig_type(wrapped.data));
      }

      constexpr auto base_prefix = config::signature_base_prefix;
      FC_ASSERT(base_prefix == prefix_str, "Signature Key has invalid prefix: ${str}", ("str", base58str)("prefix_str", prefix_str));

      auto data_str = base58str.substr(pivot + 1);
      FC_ASSERT(!data_str.empty(), "Signature has no data: ${str}", ("str", base58str));
      return base58_str_parser<signature::storage_type, config::signature_prefix>::apply(data_str);
   }

   signature::signature(const std::string& base58str)
      :_storage(parse_base58(base58str))
   {}

   signature::operator std::string() const
   {
      auto which = _storage.which();

      if (which == 2) {

         using yosemite_sig_type = signature::storage_type::template type_at<2>;
         using yosemite_sig_data_type = typename yosemite_sig_type::data_type;

         checksummed_data<yosemite_sig_data_type> wrapper;
         wrapper.data = _storage.get<yosemite_sig_type>().serialize();
         auto prefix_k1 = config::signature_prefix[1];
         wrapper.check = checksummed_data<yosemite_sig_data_type>::calculate_checksum(wrapper.data, prefix_k1);
         auto packed = raw::pack( wrapper );

         return std::string(config::signature_legacy_prefix_yosemite)
                + "_" + string(prefix_k1) + "_" + to_base58( packed.data(), packed.size() );
      }

      auto data_str = _storage.visit(base58str_visitor<storage_type, config::signature_prefix>());
      return std::string(config::signature_base_prefix) + "_" + data_str;
   }

   std::ostream& operator<<(std::ostream& s, const signature& k) {
      s << "signature(" << std::string(k) << ')';
      return s;
   }

   bool operator == ( const signature& p1, const signature& p2) {
      return eq_comparator<signature::storage_type>::apply(p1._storage, p2._storage);
   }

   bool operator != ( const signature& p1, const signature& p2) {
      return !eq_comparator<signature::storage_type>::apply(p1._storage, p2._storage);
   }

   bool operator < ( const signature& p1, const signature& p2)
   {
      return less_comparator<signature::storage_type>::apply(p1._storage, p2._storage);
   }

   size_t hash_value(const signature& b) {
       return b._storage.visit(hash_visitor());
   }
} } // eosio::blockchain

namespace fc
{
   void to_variant(const fc::crypto::signature& var, fc::variant& vo)
   {
      vo = string(var);
   }

   void from_variant(const fc::variant& var, fc::crypto::signature& vo)
   {
      vo = fc::crypto::signature(var.as_string());
   }
} // fc
