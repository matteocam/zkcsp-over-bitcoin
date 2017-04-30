
template<typename FieldT>
fair_auditing_gadget<FieldT>::fair_auditing_gadget(protoboard<FieldT> &pb) :
        gadget<FieldT>(pb, FMT("", " l_gadget"))
{
	
}

template<typename FieldT>
void fair_auditing_gadget<FieldT>::generate_r1cs_constraints()
{
}
