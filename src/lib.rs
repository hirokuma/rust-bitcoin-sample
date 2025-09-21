pub mod segwit;

pub fn run_segwit_examples() {
    let tx = segwit::v0::segwit_v0();
    println!("{:#?}", tx);

    let tx = segwit::v1::segwit_v1();
    println!("{:#?}", tx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_segwit_examples() {
        run_segwit_examples();
        // ここにassertなど追加可能
    }
}
