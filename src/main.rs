mod segwit;

use segwit::{v0, v1};

fn main() {
    v0::segwit_v0();
    v1::segwit_v1();
}
