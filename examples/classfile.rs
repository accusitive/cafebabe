use std::env;
use std::fs::File;
use std::io::Read;

fn main() {
    for arg in env::args().skip(1) {
        let mut file = File::open(&arg).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let class = classparse::parse_class(&bytes).unwrap();
        println!("Dumping {:?}\n{:?}", arg, class);
    }
}
