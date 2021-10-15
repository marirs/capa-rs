fn main() {
    for (i, arg) in std::env::args().enumerate() {
        if i == 1 {
            match capa::proceed_file(arg.as_str(), "rules", &|_s| {
                //                                           println!("{}", s);
            }) {
                Err(e) => println!("{:?}", e),
                Ok(s) => println!("{}", s),
            }
        }
    }
}
