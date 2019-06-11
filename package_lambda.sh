cargo build --release --target=x86_64-unknown-linux-musl
cp ./target/x86_64-unknown-linux-musl/$1/fastspring_keygen_integration ./bootstrap && zip lambda.zip bootstrap && rm bootstrap
