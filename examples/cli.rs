use serde_json::to_string_pretty;

fn main() {
    for (i, arg) in std::env::args().enumerate() {
        if i == 1 {
            match capa::proceed_file(
                arg.as_str(),
                "rules",
                &|_s| {
                    //                                           println!("{}", s);
                },
                true,
            ) {
                Err(e) => println!("{:?}", e),
                Ok(s) => {
                    match to_string_pretty(&s) {
                        Ok(data) => println!("{}", data),
                        Err(e) => println!("serde_json_error: {}", e),
                    }
                },
            }
        }
    }
}
