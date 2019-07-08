#include "ssles_circuit.hpp"

// libsnark gadgets


#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp> // for multipacking gadget
//#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libff/algebra/fields/field_utils.hpp> 
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp> 
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>


// ethsnarks gadgets


#include <export.hpp> 
#include <import.hpp> 
#include <stubs.hpp>  
#include <utils.hpp>  

#include <gadgets/merkle_tree.cpp> // merkle tree gadget
#include <jubjub/eddsa.cpp>   // eddsa signature gadget
#include "gadgets/mimc.hpp" // hashing gadget



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
using ethsnarks::bytes_to_bv;

typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;


//const size_t sha256_digest_len = 256;  

const size_t SSLES_TREE_DEPTH = 29; 



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
*  - `nullifier` (hashed-public): double-spend uniqueness tag 
*  - `pub_hash_var` (public): Used to reduce the number of public inputs 
*  -  'msg' A public random number (emitted by the random beacon).
*  - 'hash_var' The hash of the signed message m.

##Secret parameters:
*  - 'pk' The signer’s public key which proves the owner belongs to an authorized group 
*  - `address_bits` leaf offset (in bits, little-endian)
*  - `path_var` merkle authentication path array
*  - 'signed(m)' the signature of the message m by each participant


*/ 
  //template<typename FieldT>

  class ssles_circuit : public gadget<FieldT>
  {
  public:

    // Constructor

   //MiMC: Efficient Encryption and Cryptographic Hashing with Minimal Multiplicative Complexity
    typedef MiMC_hash_gadget mimc_hash; 
    //typedef shared_ptr<sha256_compression_function_gadget<FieldT>> sha256_gadget; /* hashing gadget */

    const size_t tree_depth = SSLES_TREE_DEPTH;


    // public inputs 
    
    const Params& in_params;  // params a and d from Edward curve
    const EdwardsPoint& in_base;    // B
    const VariablePointT& R;     // R=r.B
    const VariableArrayT msg; // public random number m

    const VariableT pub_hash_var; // used to reduce public inputs size
    const VariableT root_var;
    const VariableArrayT m_IVs; // values from merkle_tree.cpp
    const VariableT hash_var; // hash_var= H(signed(m))
    const VariableT zero;
    // private inputs

    const VariablePointT pk; //  public key   pk=s.B
    const VariableArrayT& s; // s
    const VariableT signature; // Signature= (S,R)
    const VariableArrayT path_var;
    shared_ptr<libsnark::dual_variable_gadget<FieldT>> address_bits;
    //libsnark::dual_variable_gadget<FieldT> address_bits;
    

    // logic gadgets
    mimc_hash nullifier_hash; //# Prove that nullifier matches public input
    mimc_hash pub_hash;
    mimc_hash leaf_hash;
    mimc_hash hash_preimage;

    ethsnarks::merkle_path_authenticator<mimc_hash> m_auth;
    /* merkle_path_authenticator(
        ProtoboardT &in_pb,
        const size_t in_depth,
        const VariableArrayT in_address_bits,
        const VariableArrayT in_IVs,
        const VariableT in_leaf,
        const VariableT in_expected_root,
        const VariableArrayT in_path,
        const std::string &in_annotation_prefix = ""
    ) :
    */
    ethsnarks::EdDSA_Verify eddsa_verify; 
  /* EdDSA_Verify::EdDSA_Verify(
    ProtoboardT& in_pb,
    const Params& in_params,
    const EdwardsPoint& in_base,    // B
    const VariablePointT& in_A,     // A
    const VariablePointT& in_R,     // R
    const VariableArrayT& in_s,     // s
    const VariableArrayT& in_msg,   // m
    const std::string& annotation_prefix
) :
*/
    
    ssles_circuit(
     protoboard<FieldT> &in_pb,

     const std::string &annotation_prefix


     ) :
    gadget<FieldT>(in_pb, "ssles_gadget")


    {     

        msg(make_var_array(in_pb,  ".msg"));
        in_R(make_variable(in_pb,  ".msg"));

        pub_hash_var(make_variable(in_pb, ".pub_hash_var"));

        root_var(make_variable(in_pb,  ".root_var"));

        hash_var(make_variable(in_pb,  ".hash_var"));
        

        // IV for SHA256
        m_IVs(merkle_tree_IVs(in_pb));

        zero(make_variable(in_pb, ".zero"));

        // private inputs
        
        pk(make_variable(in_pb, ".pk"));
        signature(make_variable(in_pb, ".signature"));
        address_bits(in_pb, tree_depth, ".address_bits");
        path_var(make_var_array(in_pb, tree_depth, ".path"));
        s(make_var_array(in_pb, ".s"));
        
        


        // nullifier = H(address_bits, pk)
        nullifier_hash(in_pb, zero, {address_bits->packed, pk}, FMT(annotation_prefix, ".nullifier_hash"));

       

        // pub_hash = H(root, nullifier, msg, hash_var)
        pub_hash(in_pb, zero, {root_var, nullifier_hash.result(), msg, hash_var}, FMT(annotation_prefix, ".pub_hash"));

        // leaf_hash = H(pk)
        leaf_hash(in_pb, zero, {pk}, ".leaf_hash");
         // hash_preimage = H(signature)
        hash_preimage(in_pb, zero, {signature}, ".hash_preimage");


        // assert merkle_path_authenticate(leaf_hash, path, root)
        m_auth(in_pb, tree_depth, address_bits->bits, m_IVs, leaf_hash.result(), root_var, path_var, ".authenticator");

        // assert eddsa_verify(pk, msg, signature)
        eddsa_verify(in_pb, in_params, in_base, pk, R, s, msg, ".sig verification");


        {
        // Only one public input variable is passed, which is `pub_hash`

            in_pb.set_input_sizes( 1 );


        }

    }
    void generate_r1cs_constraints()


    {    // generate constraint systems for all gadgets
        nullifier_hash.generate_r1cs_constraints();
        // enforce bitness
        address_bits->generate_r1cs_constraints(true);

        // Ensure privately provided public inputs match the hashed input
        pub_hash.generate_r1cs_constraints();
        hash_preimage.generate_r1cs_constraints();


        
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(pub_hash_var, FieldT::one(), pub_hash.result()),
            "Enforce valid proof : pub_hash_var == H(root, nullifier)");

        // ensure correct hash computations 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(hash_var, FieldT::one(), hash_preimage.result()), "Enforce valid proof");

        // Enforce zero internally
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(zero, zero, zero - zero),
            "0 * 0 == 0 - 0 ... zero is zero!");

        leaf_hash.generate_r1cs_constraints();
        m_auth.generate_r1cs_constraints();
        eddsa_verify.generate_r1cs_constraints();
    } 

    void generate_r1cs_witness(
        const FieldT & in_root,  // merkle tree root
        const libff::bit_vector & in_hash_sig,
        const FieldT & in_pubkey,     
        const libff::bit_vector & in_address,
        const std::vector<FieldT> & in_path,
        const std::vector<FieldT> & in_m,
        const FieldT& in_R,     // R=r.B
        const std::vector<FieldT> & in_s,
        const libff::bit_vector & in_sig

        ) {
        
        // public inputs

        this->pb.val(msg) = in_m;
        this->pb.val(R) = in_R;
        // hashed public inputs
        this->pb.val(root_var) = in_root;
        this->pb.val(hash_var) = in_hash_sig;


        // Set pk to pubkey
        this->pb.val(pk) = in_pubkey;
        this->pb.val(s) = in_s;
        this->pb.val(signature) = in_sig;

        // Fill our digests with our witnessed data
        address_bits->bits.fill_with_bits(this->pb, in_address);
        address_bits->generate_r1cs_witness_from_bits();

        nullifier_hash.generate_r1cs_witness();

        // public hash= H(root, nullifier, msg, hash_var)
        this->pb.val(pub_hash_var) = mimc_hash({in_root, this->pb.val(nullifier_hash.result()), in_m, in_hash_sig});
        

        pub_hash.generate_r1cs_witness();

        for( size_t i = 0; i < tree_depth; i++ )
        {
            this->pb.val(path_var[i]) = in_path[i];
        }

        leaf_hash.generate_r1cs_witness();
        m_auth.generate_r1cs_witness();
        hash_preimage.generate_r1cs_witness();
        eddsa_verify.generate_r1cs_witness();
    }
};
// namespace ssles
} 

//using ethsnarks::ppT;
//using ethsnarks::ProtoboardT;
using namespace ssles;
using ssles::ssles_circuit;

size_t ssles_tree_depth( void ) {
    return SSLES_TREE_DEPTH;
}


char* ssles_nullifier( const char *pubkey, const char *leaf_index )
{
    ppT::init_public_params();

    const FieldT arg_secret(pubkey);
    const FieldT arg_index(leaf_index);
    const FieldT arg_result(ethsnarks::mimc_hash({arg_index, arg_secret}));

    // Convert result to mpz
    
    const auto result_bigint = arg_result.as_bigint();
    mpz_t result_mpz;
    mpz_init(result_mpz);
    result_bigint.to_mpz(result_mpz);

    // Convert to string


    char *result_str = mpz_get_str(nullptr, 10, result_mpz);
    assert( result_str != nullptr );
    mpz_clear(result_mpz);

    return result_str;
}


static char *ssles_prove_internal(
    const char *pk_file,
    const FieldT arg_root,
    const FieldT arg_secret,
    const libff::bit_vector address_bits,
    const std::vector<FieldT> arg_path
    )
{
    // Create protoboard with gadget
    ProtoboardT pb;
    ssles::ssles_circuit mod(pb, "ssles");
    mod.generate_r1cs_constraints();
    mod.generate_r1cs_witness(arg_root, arg_secret, address_bits, arg_path);
   // check if circuit is satisfied
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

    return ssles_prove_internal(pk_file, arg_root, arg_secret, address_bits, arg_path);
}


char *ssles_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_pubkey,
    const char *in_address,
    const char **in_path
    ) {
    ppT::init_public_params();

    const FieldT arg_root(in_root);
    const FieldT arg_secret(in_pubkey);

    // Fill address bits with 0s and 1s from str
    // XXX: populate bits from integer (offset of the leaf in the merkle tree)
    //      parse integer from string, rather than passing as unsigned?
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

    return ssles_prove_internal(pk_file, arg_root, arg_secret, address_bits, arg_path);
}


int ssles_genkeys( const char *pk_file, const char *vk_file )
{
    return ethsnarks::stub_genkeys<ssles::ssles_circuit>(pk_file, vk_file);
}


bool ssles_verify( const char *vk_json, const char *proof_json )
{
    return ethsnarks::stub_verify( vk_json, proof_json );
}