cargo +stable build --release --target=x86_64-unknown-linux-musl
cp ./target/x86_64-unknown-linux-musl/$1/lambda ./bootstrap && zip lambda.zip bootstrap && rm bootstrap
