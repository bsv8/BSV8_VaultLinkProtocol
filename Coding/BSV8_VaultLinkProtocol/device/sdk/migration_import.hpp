#pragma once
#include "migration.hpp"
#include "bsv.hpp"
namespace vaultlink {
// Source-key proof after device wrapping. Transport identities and public
// migration status must not substitute this semantic commitment.
inline Bytes migration_import_proof_commitment(const Value& record,const Bytes& challenge){
  const auto r=inspect_device_migration(record);
  require(r.at("direction").string()=="to-hardware"&&challenge.size()==32,"migration-conflict");
  return commitment("key-import-proof",obj({{"id",r.at("id")},{"publicKey",r.at("publicKey")},
    {"sourceHash",r.at("sourceHash")},{"policyHash",r.at("policyHash")},{"challenge",challenge}}));
}
} // namespace vaultlink
