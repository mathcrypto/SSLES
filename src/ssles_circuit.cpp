#include "ssles_circuit.hpp"

// libsnark gadgets


#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp> 
//#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp> 
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp> 
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

// ethsnarks gadgets


#include <export.hpp> 
#include <import.hpp> 
#include <stubs.hpp>  
#include <utils.hpp>  

#include <gadgets/merkle_tree.cpp> 
#include <jubjub/point.hpp>     
#include <jubjub/eddsa.hpp>  
#include <gadgets/mimc.hpp>  
#include <jubjub/params.hpp>  

#include <nlohmann/json.hpp>
using json = nlohmann::json;

//#include "gadgets/preimage_proof_gadget.hpp" 

using namespace std;
using namespace libff;
using namespace libsnark;
using namespace ethsnarks;
using libsnark::dual_variable_gadget; 
using ethsnarks::jubjub::VariablePointT;
using ethsnarks::jubjub::EdwardsPoint;
using ethsnarks::jubjub::Params;
using ethsnarks::ProtoboardT;




typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;


const size_t SSLES_TREE_DEPTH = 29; 
const size_t sha256_digest_len = 256; 
const size_t SHA256_block_size = 512;  

namespace ssles {

    /* This class implements the following circuit:
    1. The public key 'pk' belongs to one of the participants: the Merkle path path_var leads from the public key pk hash to the root hash root.
    --> assert root == merkle_authenticate(path_var, address_bits, leaf_hash) # where leaf_hash= H(pk).
    2. Signed(m) checks out against the public key pk and the random number m. 
    --> assert eddsa_verify(pk, m, signature)
    3. H(signed(m)) given in the public parameters is the hash of signed(m) given in the secret parameters. 
    --> assert hash == H(signed(m))  #prove knowledge of the preimage
    4. Signed(m) in the secret parameters is the same `m given in the public parameters.
    --> Signature verification
    
#The input parameters are:
##Public parameters:
*  - `root_var` (hashed-public): The roothash of all the participants’ public keys
*  - `pub_hash_var` (public): Used to reduce the number of public inputs 
*  -  'msg' A public random number (emitted by the random beacon).
*  - 'hash_var' The hash of the signed message m.
##Secret parameters:
*  - 'pk' The signer’s public key which proves the owner belongs to an authorized group 
*  - `address_bits` leaf offset (in bits, little-endian)
*  - `path_var` merkle authentication path array
*  - 'signed(m)' the signature of the message m by each participant
*/ 


    class ssles_circuit : public GadgetT
    {
    public:
        typedef MiMC_hash_gadget HashT; 
        typedef jubjub::PureEdDSA eddsa_verify;
    //std::shared_ptr<ethsnarks::jubjub::PureEdDSA> eddsa_verify;

        const size_t tree_depth = SSLES_TREE_DEPTH;

    // public inputs

    const VariableT pub_hash_var; //Used to reduce the number of public inputs 
    const VariableT root_var;
    const VariableT hash_var; // H(signed(msg))

    // public constants
    const VariableArrayT m_IVs;

    // constant inputs

    const VariableT zero;

    // private inputs

    const VariableT pub_key; // preimage of the leaf digest 
    const VariableT msg_var; 
    const VariableArrayT path_var; // merkle authentication path array
    dual_variable_gadget<FieldT> address_bits; // leaf offset (in bits, little-endian)

    // inputs from eddsa gadget  Signature= (S,R)
    const VariableArrayT s; // s (256bit)
    const VariableArrayT Rx; //   Rx (256bit)
    const VariableArrayT Ry; // Ry (256bit)

    
    //const Params in_params;  // params a and d from Edward curve
    //const EdwardsPoint in_base;    // B
    //const VariablePointT RSig;     // R=r.B
    //const VariableArrayT msg; // public random number m
    //const VariablePointT pk; //  public key   pk=s.B
    

    // logic gadgets
    
    HashT pub_hash;
    HashT sig_msg_hash; 
    HashT leaf_hash;
    merkle_path_auth<HashT> m_authenticator; 

    ssles_circuit(
        ProtoboardT &in_pb,
        const std::string &annotation_prefix
        ) :
    GadgetT(in_pb, annotation_prefix),

        // public inputs
    pub_hash_var(make_variable(in_pb, FMT(annotation_prefix, ".pub_hash_var"))),

        // hashed public inputs
    root_var(make_variable(in_pb, FMT(annotation_prefix, ".root_var"))),
    hash_var(make_variable(in_pb, FMT(annotation_prefix, ".hash_var"))),

    // Initialisation vector for merkle tree hard-coded constants
    // Means that H('a', 'b') on level1 will have a different output than the same values on level2
    m_IVs(merkle_tree_IVs(in_pb)),

    // constant zero, used as IV for hash functions
    zero(make_variable(in_pb, FMT(annotation_prefix, ".zero"))),

        // private inputs
    pub_key(make_variable(in_pb, FMT(annotation_prefix, ".pub_key"))),
    address_bits(in_pb, tree_depth, FMT(annotation_prefix, ".address_bits")), 
    path_var(make_var_array(in_pb, tree_depth, FMT(annotation_prefix, ".path"))),
    msg_var(make_variable(in_pb, FMT(annotation_prefix, ".msg_var"))),
    sig_msg_hash(in_pb, zero, {msg_var}, FMT(annotation_prefix, ".msg_var")), 

        // pub_hash = H(root, hash_var)
    
    pub_hash(in_pb, zero, {root_var, sig_msg_hash.result()}, FMT(annotation_prefix, ".pub_hash")),

        // leaf_hash = H(secret)
    
    leaf_hash(in_pb, zero, {pub_key}, FMT(annotation_prefix, ".leaf_hash")),

        // assert merkle_path_authenticate(leaf_hash, path, root)
    
    m_auth(in_pb, tree_depth, address_bits.bits, m_IVs, leaf_hash.result(), root_var, path_var, FMT(annotation_prefix, ".authenticator"))
    {
        // Only one public input variable is passed, which is `pub_hash`
        // The actual values are provided as private inputs
        in_pb.set_input_sizes( 1 );

        
    }

    void generate_r1cs_constraints()
    {
        
        sig_msg_hash.generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(
            ConstraintT(hash_var, FieldT::one(), sig_msg_hash.result()),
            ".hash_var == H(msg_var)");
        address_bits.generate_r1cs_constraints(true);

        // Ensure privately provided public inputs match the hashed input
        pub_hash.generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(
            ConstraintT(pub_hash_var, FieldT::one(), pub_hash.result()),
            ".pub_hash_var == H(root, sig_msg_hash)");



        // Enforce zero internally
        this->pb.add_r1cs_constraint(
            ConstraintT(zero, zero, zero - zero),
            "0 * 0 == 0 - 0 ... zero is zero!");

        leaf_hash.generate_r1cs_constraints();
        m_auth.generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        const FieldT in_root,         // merkle tree root
        const FieldT in_prehash,      
        const FieldT in_secret,     
        const FieldT in_msg,     
        const libff::bit_vector in_address,
        const std::vector<FieldT> &in_path
        ) {
        // hashed public inputs
        this->pb.val(root_var) = in_root;
        this->pb.val(hash_var) = in_prehash;
        

        // private inputs
        this->pb.val(pub_key) = in_secret;
        this->pb.val(msg_var) = in_msg;
        address_bits.bits.fill_with_bits(this->pb, in_address);
        address_bits.generate_r1cs_witness_from_bits();

        
        sig_msg_hash.generate_r1cs_witness();

        // public hash
        this->pb.val(pub_hash_var) = mimc_hash({in_root, this->pb.val(sig_msg_hash.result())});
        pub_hash.generate_r1cs_witness();

        for( size_t i = 0; i < tree_depth; i++ )
        {
            this->pb.val(path_var[i]) = in_path[i];
        }
        leaf_hash.generate_r1cs_witness();



        m_auth.generate_r1cs_witness();
    }
};

// namespace ssles
}


size_t ssles_tree_depth( void ) {
    return SSLES_TREE_DEPTH;
}





static char *ssles_prove_internal(
    const char *pk_file,
    const FieldT arg_root,
    const FieldT arg_prehash,
    const FieldT arg_secret,
    const FieldT arg_msg,
    const libff::bit_vector address_bits,
    const std::vector<FieldT> arg_path
    )
{
    // Create protoboard with gadget
    ProtoboardT pb;
    ssles::ssles_circuit mod(pb, "ssles");
    mod.generate_r1cs_constraints();
    mod.generate_r1cs_witness(arg_root, arg_prehash, arg_secret, arg_msg, address_bits, arg_path);

    if( ! pb.is_satisfied() )
    {
        std::cerr << "Not Satisfied!" << std::endl;
        return nullptr;
    }

    std::cerr << pb.num_constraints() << " constraints" << std::endl;

    // Return proof as a JSON document, which must be destroyed by the caller
    const auto proof_as_json = ethsnarks::stub_prove_from_pb(pb, pk_file);
    return ::strdup(proof_as_json.c_str());
}


char *ssles_prove_json( const char *pk_file, const char *in_json )
{
    ppT::init_public_params();

    const auto root = json::parse(in_json);
    const auto arg_root = ethsnarks::parse_FieldT(root.at("root"));
    const auto arg_secret = ethsnarks::parse_FieldT(root.at("secret")); 
    const auto arg_prehash = ethsnarks::parse_FieldT(root.at("prehash"));
    const auto arg_msg = ethsnarks::parse_FieldT(root.at("message"));

    const auto arg_path = ethsnarks::create_F_list(root.at("path"));
    if( arg_path.size() != SSLES_TREE_DEPTH )
    {
        std::cerr << "Path length doesn't match tree depth" << std::endl;
        return nullptr;
    }

    // Fill address bits from integer
    unsigned long address = root.at("address").get<decltype(address)>();
    assert( (sizeof(address) * 8) >= SSLES_TREE_DEPTH );
    libff::bit_vector address_bits;
    address_bits.resize(SSLES_TREE_DEPTH);
    for( size_t i = 0; i < SSLES_TREE_DEPTH; i++ )
    {
        address_bits[i] = (address & (1u<<i)) != 0;
    }

    return ssles_prove_internal(pk_file, arg_root, arg_prehash, arg_secret, arg_msg, address_bits, arg_path);
}


char *ssles_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_prehash,
    const char *in_secret,
    const char *in_msg,
    const char *in_address,
    const char **in_path
    ) {
    ppT::init_public_params();

    const FieldT arg_root(in_root);
    const FieldT arg_secret(in_secret);
    const FieldT arg_prehash(in_prehash);
    const FieldT arg_msg(in_msg);

    // Fill address bits with 0s and 1s from str
    
    libff::bit_vector address_bits;
    address_bits.resize(SSLES_TREE_DEPTH);
    if( strlen(in_address) != SSLES_TREE_DEPTH )
    {
        std::cerr << "Address length doesnt match depth" << std::endl;
        return nullptr;
    }
    for( size_t i = 0; i < SSLES_TREE_DEPTH; i++ )
    {
        if( in_address[i] != '0' && in_address[i] != '1' ) {
            std::cerr << "Address bit " << i << " invalid, unknown: " << in_address[i] << std::endl;
            return nullptr;
        }
        address_bits[i] = '0' - in_address[i];
    }

    // Fill path from field elements from in_path
    std::vector<FieldT> arg_path;
    arg_path.resize(SSLES_TREE_DEPTH);
    for( size_t i = 0; i < SSLES_TREE_DEPTH; i++ ) {
        assert( in_path[i] != nullptr );
        arg_path[i] = FieldT(in_path[i]);
    }

    return ssles_prove_internal(pk_file, arg_root, arg_prehash, arg_secret, arg_msg, address_bits, arg_path);
}


int ssles_genkeys( const char *pk_file, const char *vk_file )
{
    return ethsnarks::stub_genkeys<ssles::ssles_circuit>(pk_file, vk_file);
}


bool ssles_verify( const char *vk_json, const char *proof_json )
{
    return ethsnarks::stub_verify( vk_json, proof_json );
}
