mod consts;
use consts::{Table, DEC_TABLE, ENC_TABLE, RKEY_GEN,P,P_INV};

use cipher::{
    consts::{U16, U4, U32},
    array::Array,
    inout::InOut,
    typenum::Unsigned,
    BlockBackend, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

type BlockSize = U16;
type KeySize = U32;

/// 128-bit Kuznyechik block
pub type Block = Array<u8, U16>;
pub type Block_2 = Array<u8, U32>;
/// 256-bit Kuznyechik key
pub type Key = Array<u8, U32>;

pub type RoundKeys = [__m128i; 10];
pub type RoundKeys_2 =[__m256i;10];

type ParBlocksSize = U4;

#[rustfmt::skip]
macro_rules! unroll_par {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        { let $var: usize = 2; $body; }
        { let $var: usize = 3; $body; }
    };
}

#[inline(always)]
unsafe fn sub_bytes(block: __m128i, sbox: &[u8; 256]) -> __m128i {
    let t0 = _mm_extract_epi16(block, 0) as u16;
    let t1 = _mm_extract_epi16(block, 1) as u16;
    let t2 = _mm_extract_epi16(block, 2) as u16;
    let t3 = _mm_extract_epi16(block, 3) as u16;
    let t4 = _mm_extract_epi16(block, 4) as u16;
    let t5 = _mm_extract_epi16(block, 5) as u16;
    let t6 = _mm_extract_epi16(block, 6) as u16;
    let t7 = _mm_extract_epi16(block, 7) as u16;
    _mm_set_epi8(
        sbox[(t7 >> 8) as usize] as i8,
        sbox[(t7 & 0xFF) as usize] as i8,
        sbox[(t6 >> 8) as usize] as i8,
        sbox[(t6 & 0xFF) as usize] as i8,
        sbox[(t5 >> 8) as usize] as i8,
        sbox[(t5 & 0xFF) as usize] as i8,
        sbox[(t4 >> 8) as usize] as i8,
        sbox[(t4 & 0xFF) as usize] as i8,
        sbox[(t3 >> 8) as usize] as i8,
        sbox[(t3 & 0xFF) as usize] as i8,
        sbox[(t2 >> 8) as usize] as i8,
        sbox[(t2 & 0xFF) as usize] as i8,
        sbox[(t1 >> 8) as usize] as i8,
        sbox[(t1 & 0xFF) as usize] as i8,
        sbox[(t0 >> 8) as usize] as i8,
        sbox[(t0 & 0xFF) as usize] as i8,
    )
}

#[inline(always)]
unsafe fn sub_bytes_256(blocks: __m256i, sbox: &[u8; 256]) -> __m256i {
    let t0_0 = _mm256_extract_epi16(blocks, 0) as u16;
    let t1_0 = _mm256_extract_epi16(blocks, 1) as u16;
    let t2_0 = _mm256_extract_epi16(blocks, 2) as u16;
    let t3_0 = _mm256_extract_epi16(blocks, 3) as u16;
    let t4_0 = _mm256_extract_epi16(blocks, 4) as u16;
    let t5_0 = _mm256_extract_epi16(blocks, 5) as u16;
    let t6_0 = _mm256_extract_epi16(blocks, 6) as u16;
    let t7_0 = _mm256_extract_epi16(blocks, 7) as u16;
    let t0_1 = _mm256_extract_epi16(blocks, 8) as u16;
    let t1_1 = _mm256_extract_epi16(blocks, 9) as u16;
    let t2_1 = _mm256_extract_epi16(blocks, 10) as u16;
    let t3_1 = _mm256_extract_epi16(blocks, 11) as u16;
    let t4_1 = _mm256_extract_epi16(blocks, 12) as u16;
    let t5_1 = _mm256_extract_epi16(blocks, 13) as u16;
    let t6_1 = _mm256_extract_epi16(blocks, 14) as u16;
    let t7_1 = _mm256_extract_epi16(blocks, 15) as u16;
    
 

    _mm256_set_epi8(
        sbox[(t7_0 >> 8) as usize] as i8,
        sbox[(t7_0 & 0xFF) as usize] as i8,
        sbox[(t6_0 >> 8) as usize] as i8,
        sbox[(t6_0 & 0xFF) as usize] as i8,
        sbox[(t5_0 >> 8) as usize] as i8,
        sbox[(t5_0 & 0xFF) as usize] as i8,
        sbox[(t4_0 >> 8) as usize] as i8,
        sbox[(t4_0 & 0xFF) as usize] as i8,
        sbox[(t3_0 >> 8) as usize] as i8,
        sbox[(t3_0 & 0xFF) as usize] as i8,
        sbox[(t2_0 >> 8) as usize] as i8,
        sbox[(t2_0 & 0xFF) as usize] as i8,
        sbox[(t1_0 >> 8) as usize] as i8,
        sbox[(t1_0 & 0xFF) as usize] as i8,
        sbox[(t0_0 >> 8) as usize] as i8,
        sbox[(t0_0 & 0xFF) as usize] as i8,
        sbox[(t7_1 >> 8) as usize] as i8,
        sbox[(t7_1 & 0xFF) as usize] as i8,
        sbox[(t6_1 >> 8) as usize] as i8,
        sbox[(t6_1 & 0xFF) as usize] as i8,
        sbox[(t5_1 >> 8) as usize] as i8,
        sbox[(t5_1 & 0xFF) as usize] as i8,
        sbox[(t4_1 >> 8) as usize] as i8,
        sbox[(t4_1 & 0xFF) as usize] as i8,
        sbox[(t3_1 >> 8) as usize] as i8,
        sbox[(t3_1 & 0xFF) as usize] as i8,
        sbox[(t2_1 >> 8) as usize] as i8,
        sbox[(t2_1 & 0xFF) as usize] as i8,
        sbox[(t1_1 >> 8) as usize] as i8,
        sbox[(t1_1 & 0xFF) as usize] as i8,
        sbox[(t0_1 >> 8) as usize] as i8,
        sbox[(t0_1 & 0xFF) as usize] as i8,
    )
}
#[inline(always)]
unsafe fn transform(block: __m128i, table: &Table) -> __m128i {
    macro_rules! get {
        ($table:expr, $ind:expr, $i:expr) => {{
            let idx = _mm_extract_epi16($ind, $i) as u16 as usize;
            let p = &($table.0[idx]) as *const u8 as *const __m128i;
            // correct alignment of `p` is guaranteed since offset values
            // are shifted by 4 bits left and the table is aligned to 16 bytes
            debug_assert_eq!(p as usize % 16, 0);
            _mm_load_si128(p)
            
        }};
    }

    macro_rules! xor_get {
        ($val:expr, $table:expr, $ind:expr, $i:expr) => {
            $val = _mm_xor_si128($val, get!($table, $ind, $i));
        };
    }
    
    let ind = _mm_set_epi64x(0x0f0e0d0c0b0a0908, 0x0706050403020100);
    let test=_mm_unpacklo_epi8(block, ind);

    let lind = _mm_slli_epi16(test, 4);
    

    let mut lt = get!(table, lind, 0);
  

    xor_get!(lt, table, lind, 1);
    xor_get!(lt, table, lind, 2);
    xor_get!(lt, table, lind, 3);
    xor_get!(lt, table, lind, 4);
    xor_get!(lt, table, lind, 5);
    xor_get!(lt, table, lind, 6);
    xor_get!(lt, table, lind, 7);

    let rind = _mm_slli_epi16(_mm_unpackhi_epi8(block, ind), 4);

    let mut rt = get!(table, rind, 0);
    xor_get!(rt, table, rind, 1);
    xor_get!(rt, table, rind, 2);
    xor_get!(rt, table, rind, 3);
    xor_get!(rt, table, rind, 4);
    xor_get!(rt, table, rind, 5);
    xor_get!(rt, table, rind, 6);
    xor_get!(rt, table, rind, 7);

    _mm_xor_si128(lt, rt)
}

#[inline(always)]
unsafe fn transform_256(blocks: __m256i, table: &Table) -> __m256i {
    macro_rules! get {
        ($table:expr, $ind:expr, $i:expr) => {{
            let up_hf=_mm256_extracti128_si256($ind,1);
            let idx1 = _mm_extract_epi16(up_hf, $i) as u16 as usize;
            let p1 = &($table.0[idx1]) as *const u8 as *const __m128i;
            // correct alignment of `p` is guaranteed since offset values
            // are shifted by 4 bits left and the table is aligned to 16 bytes
            debug_assert_eq!(p1 as usize % 16, 0);
            let lr_hf=_mm256_extracti128_si256($ind,0);
            let idx2 = _mm_extract_epi16(lr_hf, $i) as u16 as usize;
           
            let p2 = &($table.0[idx2]) as *const u8 as *const __m128i;
            debug_assert_eq!(p2 as usize % 16, 0);
            _mm256_loadu2_m128i(p1,p2)
        }};
    }

    macro_rules! xor_get {
        ($val:expr, $table:expr, $ind:expr, $i:expr) => {
            $val = _mm256_xor_si256($val, get!($table, $ind, $i));
        };
    }

    let ind = _mm256_set_epi64x(0x0f0e0d0c0b0a0908, 0x0706050403020100,0x0f0e0d0c0b0a0908, 0x0706050403020100);//делаем set для 256 от f до 0 от f до 0
   
    let test = _mm256_unpacklo_epi8(blocks, ind);

    let lind = _mm256_slli_epi16(test, 4);

    let mut lt = get!(table, lind, 0);//переделываем, делаем как загрузку для двух 128 битных и потом сгружаем в один регист
   
    xor_get!(lt, table, lind, 1);
    xor_get!(lt, table, lind, 2);
    xor_get!(lt, table, lind, 3);
    xor_get!(lt, table, lind, 4);
    xor_get!(lt, table, lind, 5);
    xor_get!(lt, table, lind, 6);
    xor_get!(lt, table, lind, 7);

    let rind = _mm256_slli_epi16(_mm256_unpackhi_epi8(blocks, ind), 4);

    let mut rt = get!(table, rind, 0);
    xor_get!(rt, table, rind, 1);
    xor_get!(rt, table, rind, 2);
    xor_get!(rt, table, rind, 3);
    xor_get!(rt, table, rind, 4);
    xor_get!(rt, table, rind, 5);
    xor_get!(rt, table, rind, 6);
    xor_get!(rt, table, rind, 7);

    _mm256_xor_si256(lt, rt)//получили два блока
}

pub fn expand_enc_keys(key: &Key) -> RoundKeys {
    macro_rules! next_const {
        ($i:expr) => {{
            let p = RKEY_GEN.0.as_ptr() as *const __m128i;
            // correct alignment of `p` is guaranteed since the table
            // is aligned to 16 bytes
            let p = p.add($i);
            debug_assert_eq!(p as usize % 16, 0);
            $i += 1;
            _mm_load_si128(p)
        }};
    }

    unsafe {
        let mut enc_keys = [_mm_setzero_si128(); 10];

        let pk: *const __m128i = key.as_ptr() as *const __m128i;
        let mut k1 = _mm_loadu_si128(pk);
        let mut k2 = _mm_loadu_si128(pk.add(1));
        enc_keys[0] = k1;
        enc_keys[1] = k2;

        let mut cidx = 0;
        for i in 1..5 {
            for _ in 0..4 {
                let mut t = _mm_xor_si128(k1, next_const!(cidx));
                t = transform(t, &ENC_TABLE);
                k2 = _mm_xor_si128(k2, t);

                let mut t = _mm_xor_si128(k2, next_const!(cidx));
                t = transform(t, &ENC_TABLE);
                k1 = _mm_xor_si128(k1, t);
            }

            enc_keys[2 * i] = k1;
            enc_keys[2 * i + 1] = k2;
        }

        enc_keys
    }
}
fn dup_keys(keys: &RoundKeys)->RoundKeys_2{
    unsafe{

        let mut keys_2=[_mm256_setzero_si256();10];
        for i in 0..=9{
            keys_2[i]=_mm256_set_m128i(keys[i],keys[i]);
        }
        keys_2
    }
}

pub fn inv_enc_keys(enc_keys: &RoundKeys) -> RoundKeys {
    unsafe {
        let mut dec_keys = [_mm_setzero_si128(); 10];

        dec_keys[0] = enc_keys[9];
        for i in 1..9 {
            let k = sub_bytes(enc_keys[i], &P);
            dec_keys[9 - i] = transform(k, &DEC_TABLE);
        }
        dec_keys[9] = enc_keys[0];

        dec_keys
    }
}



pub(crate) struct EncBackend<'a>(pub(crate) &'a RoundKeys);


impl<'a> BlockSizeUser for EncBackend<'a> {
    type BlockSize = U16;
}


impl<'a> ParBlocksSizeUser for EncBackend<'a> {
    type ParBlocksSize = ParBlocksSize;
}

impl<'a> BlockBackend for EncBackend<'a> {
    #[inline]
    fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = block.into_raw();
            let mut b = _mm_loadu_si128(in_ptr as *const __m128i);

            for i in 0..9 {
                b = _mm_xor_si128(b, k[i]);
                b = transform(b, &ENC_TABLE);
            }
            b = _mm_xor_si128(b, k[9]);
            _mm_storeu_si128(out_ptr as *mut __m128i, b);
        }
    }
}

pub(crate) struct DecBackend<'a>(pub(crate) &'a RoundKeys);

impl<'a> BlockSizeUser for DecBackend<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for DecBackend<'a> {
    type ParBlocksSize = ParBlocksSize;
}

impl<'a> BlockBackend for DecBackend<'a> {
    #[inline]
    fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = block.into_raw();
            let mut b = _mm_loadu_si128(in_ptr as *const __m128i);

            b = _mm_xor_si128(b, k[0]);

            b = sub_bytes(b, &P);
            b = transform(b, &DEC_TABLE);

            for i in 1..9 {
                b = transform(b, &DEC_TABLE);
                b = _mm_xor_si128(b, k[i]);
            }
            b = sub_bytes(b, &P_INV);
            b = _mm_xor_si128(b, k[9]);

            _mm_storeu_si128(out_ptr as *mut __m128i, b)
        }
    }

}
 
fn enc_block(keys :&RoundKeys,blocks:InOut<'_, '_, Block_2>){
    let (in_ptr, out_ptr)  = blocks.into_raw();
    let k=dup_keys(&keys);
    unsafe{
    let mut b = _mm256_loadu_si256(in_ptr as *const __m256i);
    
    for i in 0..9 {
        b = _mm256_xor_si256(b, k[i]);
        b = transform_256(b, &ENC_TABLE);
    }
        b = _mm256_xor_si256(b, k[9]);
    _mm256_storeu_si256(out_ptr as *mut __m256i, b);}
}

fn dec_block(keys :&RoundKeys,blocks:InOut<'_, '_, Block_2>){
    let (in_ptr, out_ptr)  = blocks.into_raw();
    let k=dup_keys(&keys);
    unsafe {
        let mut b =_mm256_loadu_si256(in_ptr as *const __m256i);

        b = _mm256_xor_si256(b, k[0]);

        b = sub_bytes_256(b, &P);
        b = transform_256(b, &DEC_TABLE);

        for i in 1..9 {
            b = transform_256(b, &DEC_TABLE);
            b = _mm256_xor_si256(b, k[i]);
        }
        b = sub_bytes_256(b, &P_INV);
        b = _mm256_xor_si256(b, k[9]);

        _mm256_storeu_si256(out_ptr as *mut __m256i, b);
    }
}


fn main(){
    let key:Key=[0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B,
    0x9C, 0xAD, 0xBE, 0xCF, 0xDA, 0xEB, 0xFC, 0x0D,
    0x1E, 0x2F, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
    0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xFA, 0x0B].into();
    let keys= expand_enc_keys(&key);
    let inv_keys=inv_enc_keys(&keys);
    let mut array:Block_2=[0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B,
    0x9C, 0xAD, 0xBE, 0xCF, 0xDA, 0xEB, 0xFC, 0x0D,0x0E, 0x1F, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F,
    0x8A, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xEA, 0xFB].into();
    println!("Two blocks {:?}",array);
    unsafe{
        enc_block(&keys,InOut::from_raw(&  array,& mut array));        
        println!("After encoding {:?}", array);
        dec_block(&inv_keys,InOut::from_raw(&  array,& mut array));
        println!("After decoding {:?}", array); 
    }
}