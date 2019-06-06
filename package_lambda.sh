cargo build --release --target=x86_64-unknown-linux-musl
cp ./target/x86_64-unknown-linux-musl/$1/sendowl_keygen_glue ./bootstrap && zip lambda.zip bootstrap && rm bootstrap
