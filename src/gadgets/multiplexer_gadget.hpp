//
//  multiplexer_gadget.hpp
//  gadgets
//

#ifndef multiplexer_gadget_hpp
#define multiplexer_gadget_hpp

#include <stdio.h>
#include <stddef.h>
#include <vector>

#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp"

using namespace libsnark;

namespace ssles {
    
    template<typename FieldT>
    class multiplexer_gadget : public gadget<FieldT> {
    public:
        size_t digest_size;
        digest_variable<FieldT> output;
        pb_linear_combination<FieldT> is_right;
        digest_variable<FieldT> left;
        digest_variable<FieldT> right;
        
        multiplexer_gadget(protoboard<FieldT> &pb,
                           const size_t digest_size,
                           const digest_variable<FieldT> &output,
                           const pb_linear_combination<FieldT> &is_right,
                           const digest_variable<FieldT> &left,
                           const digest_variable<FieldT> &right,
                           const std::string &annotation_prefix);
        
        
        void generate_r1cs_constraints();
        void generate_r1cs_witness();
    };
    
} // ssles

#include "multiplexer_gadget.tcc"

#endif // MULTIPLEXER_GADGET_HPP_





