extern crate test;

use super::*;
use test::Bencher;

#[bench]
fn bench_oppoll_serialize(b: &mut Bencher) {
    let pkt = OpPoll::new();

    b.iter(|| pkt.serialize());

}


// #[bench]
// fn bench_oppoll_deserialize(b: &mut Bencher) {
//     let pkt = OpPoll::new();
//     let bytes = test::black_box(pkt.serialize());

//     let mut pkt_out : Option<OpPoll> = None;

//     b.iter(|| OpPoll::deserialize(&bytes));

// }
