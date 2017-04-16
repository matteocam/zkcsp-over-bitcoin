
template<typename FieldT>
r1cs_primary_input<FieldT> ModularSumInput<FieldT>::mapToSnarkFmt() const
{
		
    bit_vector input_as_bits = int_list_to_bits({x, y, a, p}, 32);
    
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}

