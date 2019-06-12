//
//  multiplexer_gadget.cpp
//  gadgets
//
//  Created by Amira Bouguera on 23/05/2019.
//  Copyright © 2019 Amira Bouguera. All rights reserved.


#ifndef Multiplexer_GADGET_TCC_
#define Multiplexer_GADGET_TCC_

#include "multiplexer_gadget.hpp"

namespace ssles {

template<typename FieldT>
multiplexer_gadget<FieldT>::multiplexer_gadget(protoboard<FieldT> &pb,
const size_t digest_size,
const digest_variable<FieldT> &output,
const pb_linear_combination<FieldT> &is_right,
const digest_variable<FieldT> &left,
const digest_variable<FieldT> &right,
const std::string &annotation_prefix) :
gadget<FieldT>(pb, annotation_prefix), digest_size(digest_size), output(output), is_right(is_right), left(left), right(right)
{
}




template<typename FieldT>
void multiplexer_gadget<FieldT>::generate_r1cs_constraints()
{
for (size_t i = 0; i < digest_size; ++i)
{
/*
output = is_right * right + (1-is_right) * left
output - left = is_right(right - left)
*/
this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(is_right, right.bits[i] - left.bits[i], output.bits[i] - left.bits[i]),
FMT(this->annotation_prefix, " propagate_%zu", i));
}
}


template<typename FieldT>
void multiplexer_gadget<FieldT>::generate_r1cs_witness()
{
is_right.evaluate(this->pb);

assert(this->pb.lc_val(is_right) == FieldT::one() || this->pb.lc_val(is_right) == FieldT::zero());
if (this->pb.lc_val(is_right) == FieldT::one())
{
for (size_t i = 0; i < digest_size; ++i)
{
this->pb.val(output.bits[i]) = this->pb.val(right.bits[i]);
}
}
else
{
for (size_t i = 0; i < digest_size; ++i)
{
this->pb.val(output.bits[i]) = this->pb.val(left.bits[i]);
}
}
}

} // ssles


#endif // Multiplexer_GADGET_TCC_


