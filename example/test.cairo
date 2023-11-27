%builtins range_check bitwise

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_keccak.keccak import cairo_keccak_uint256s_bigend, finalize_keccak
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import BigInt3, uint256_to_bigint
from starkware.cairo.common.cairo_secp.signature import public_key_point_to_eth_address
from starkware.cairo.common.uint256 import Uint256, felt_to_uint256

func proof{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(nonce: felt, hash: Uint256) -> () {
    alloc_locals;
    let (keccak_ptr: felt*) = alloc();
    local keccak_ptr_start: felt* = keccak_ptr;

    local x_high;
    %{ ids.x_high = program_input['x_high'] %}
    local x_low;
    %{ ids.x_low = program_input['x_low'] %}
    local y_high;
    %{ ids.y_high = program_input['y_high'] %}
    local y_low;
    %{ ids.y_low = program_input['y_low'] %}

    let public_key_x_bigint3: BigInt3 = uint256_to_bigint(x=Uint256(low=x_low, high=x_high));
    let public_key_y_bigint3: BigInt3 = uint256_to_bigint(x=Uint256(low=y_low, high=y_high));

    let public_key: EcPoint = EcPoint(public_key_x_bigint3, public_key_y_bigint3);

    with keccak_ptr {
        let (local cal_eth_address: felt) = public_key_point_to_eth_address(
            public_key_point=public_key
        );
        let address_uint256 = felt_to_uint256(cal_eth_address);
        let nonce_uint256 = felt_to_uint256(nonce);
        let (local arr: Uint256*) = alloc();
        assert arr[0] = address_uint256;
        assert arr[1] = nonce_uint256;
        let (local cal_hash: Uint256) = cairo_keccak_uint256s_bigend(n_elements=2, elements=arr);
        finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr);
    }

    assert hash = cal_hash;

    return ();
}

func main{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    let nonce = 0x1;
    let hash = Uint256(
        low=0x71d32ad8bfb708c2a5089b0cfd3724f5, high=0xf1f23c1ed6d94232b00896e6b82d7020
    );
    proof(nonce=nonce, hash=hash);

    return ();
}
