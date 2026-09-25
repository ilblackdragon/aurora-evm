//! Strict canonical ABI validation: offsets cannot alias heads/other tails,
//! padding is zero, lengths are bounded, and trailing bytes are rejected.
use super::{address, Address, Arg, Denied, Result};
use crate::prelude::*;

pub(super) fn valid_schema(args: &[Arg]) -> bool {
    fn valid(a: &Arg, depth: usize, budget: &mut usize) -> bool {
        if depth > 8 || *budget == 0 {
            return false;
        }
        *budget -= 1;
        match a {
            Arg::Uint(n) => *n > 0 && *n <= 256 && *n % 8 == 0,
            Arg::FixedBytes(n) => *n > 0 && *n <= 32,
            Arg::Tuple(items) => items.iter().all(|i| valid(i, depth + 1, budget)),
            Arg::Array(item) => valid(item, depth + 1, budget),
            _ => true,
        }
    }
    let mut budget = 256;
    args.iter().all(|a| valid(a, 0, &mut budget))
}
fn dynamic(a: &Arg) -> bool {
    match a {
        Arg::Bytes | Arg::Array(_) => true,
        Arg::Tuple(v) => v.iter().any(dynamic),
        _ => false,
    }
}
fn head_size(a: &Arg) -> usize {
    if dynamic(a) {
        32
    } else {
        match a {
            Arg::Tuple(v) => v.iter().map(head_size).sum(),
            _ => 32,
        }
    }
}
fn length(data: &[u8]) -> Result<usize> {
    let word = data.get(..32).ok_or(Denied)?;
    if word[..28].iter().any(|b| *b != 0) {
        return Err(Denied);
    }
    let n = u32::from_be_bytes(word[28..].try_into().map_err(|_| Denied)?);
    usize::try_from(n).map_err(|_| Denied)
}
fn sequence(args: &[&Arg], data: &[u8]) -> Result<(usize, Vec<Option<Address>>)> {
    let head: usize = args.iter().map(|a| head_size(a)).sum();
    if data.len() < head {
        return Err(Denied);
    }
    let mut pos = 0;
    let mut tail = head;
    let mut addresses = Vec::new();
    for a in args {
        if dynamic(a) {
            let offset = length(&data[pos..])?;
            if offset != tail {
                return Err(Denied);
            }
            let n = value(a, data.get(tail..).ok_or(Denied)?)?;
            tail = tail.checked_add(n).ok_or(Denied)?;
            addresses.push(None);
            pos += 32;
        } else {
            let n = value(a, &data[pos..])?;
            addresses.push(if matches!(a, Arg::Address) {
                Some(address(&data[pos..pos + 32])?)
            } else {
                None
            });
            pos += n;
        }
    }
    Ok((tail, addresses))
}
fn value(a: &Arg, data: &[u8]) -> Result<usize> {
    match a {
        Arg::Tuple(args) => sequence(&args.iter().collect::<Vec<_>>(), data).map(|v| v.0),
        Arg::Array(item) => {
            let n = length(data)?;
            if n > 1024 {
                return Err(Denied);
            }
            let args: Vec<_> = (0..n).map(|_| item.as_ref()).collect();
            sequence(&args, data.get(32..).ok_or(Denied)?).map(|v| v.0 + 32)
        }
        Arg::Bytes => {
            let n = length(data)?;
            if n > 65536 {
                return Err(Denied);
            }
            let padded = n.checked_add(31).ok_or(Denied)? / 32 * 32;
            let bytes = data.get(32..32 + padded).ok_or(Denied)?;
            if bytes[n..].iter().any(|b| *b != 0) {
                return Err(Denied);
            }
            Ok(32 + padded)
        }
        _ => {
            let word = data.get(..32).ok_or(Denied)?;
            match a {
                Arg::Address => {
                    address(word)?;
                }
                Arg::Uint(n) => {
                    if *n == 0
                        || *n > 256
                        || *n % 8 != 0
                        || word[..32 - usize::from(*n) / 8].iter().any(|b| *b != 0)
                    {
                        return Err(Denied);
                    }
                }
                Arg::Bool => {
                    if word[..31].iter().any(|b| *b != 0) || word[31] > 1 {
                        return Err(Denied);
                    }
                }
                Arg::FixedBytes(n)
                    if *n == 0 || *n > 32 || word[usize::from(*n)..].iter().any(|b| *b != 0) =>
                {
                    return Err(Denied);
                }
                _ => {}
            }
            Ok(32)
        }
    }
}
pub(super) fn validate(args: &[Arg], data: &[u8]) -> Result<Vec<Option<Address>>> {
    if data.len() > 65536 || !valid_schema(args) {
        return Err(Denied);
    }
    let (used, addresses) = sequence(&args.iter().collect::<Vec<_>>(), data)?;
    if used != data.len() {
        return Err(Denied);
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethabi::Token;

    #[test]
    fn nested_dynamic_abi_rejects_aliasing_padding_truncation_and_oversized_lengths() {
        let schema = vec![
            Arg::Address,
            Arg::Array(Box::new(Arg::Tuple(vec![Arg::Bytes, Arg::Uint(16)]))),
        ];
        let encoded = ethabi::encode(&[
            Token::Address(ethabi::Address::repeat_byte(1)),
            Token::Array(vec![Token::Tuple(vec![
                Token::Bytes(vec![7]),
                Token::Uint(9.into()),
            ])]),
        ]);
        assert_eq!(validate(&schema, &encoded).unwrap()[0], Some([1; 20]));
        for end in 0..encoded.len() {
            assert!(validate(&schema, &encoded[..end]).is_err());
        }
        let mut changed = encoded.clone();
        changed.push(0);
        assert!(validate(&schema, &changed).is_err());
        for (position, value) in [(0, 1), (63, 0), (95, 255), (127, 0), (189, 255), (255, 1)] {
            let mut changed = encoded.clone();
            changed[position] = value;
            assert!(
                validate(&schema, &changed).is_err(),
                "accepted mutation at {position}"
            );
        }
        let mut huge = ethabi::encode(&[Token::Bytes(vec![])]);
        huge[60..64].fill(255);
        assert!(validate(&[Arg::Bytes], &huge).is_err());
        let mut alias = ethabi::encode(&[Token::Bytes(vec![1]), Token::Bytes(vec![2])]);
        alias[63] = 64;
        assert!(validate(&[Arg::Bytes, Arg::Bytes], &alias).is_err());
        assert!(validate(&[Arg::Bool], &[2; 32]).is_err());
        assert!(validate(&[Arg::FixedBytes(1)], &[1; 32]).is_err());
        assert!(!valid_schema(&[Arg::Uint(7)]));
        let mut deep = Arg::Address;
        for _ in 0..10 {
            deep = Arg::Array(Box::new(deep));
        }
        assert!(!valid_schema(&[deep]));
    }
}
