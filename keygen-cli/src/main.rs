use clap::{App, Arg, SubCommand};
use fastspring_keygen_integration::keygen::generate_licenses;
use dotenv::dotenv;

const POLICY_COMMUNITY: &str = "94a3abe1-2646-4868-94fe-e2032e82c2e2";
const POLICY_STUDIO: &str = "b60267b3-2a7a-468b-b868-7eb5db1a9a75";
const POLICY_INDIE: &str = "77e58101-57e4-487d-9e64-adf3bb699a6e";

fn main() {
    dotenv().ok();
    let matches = App::new("keygen.sh command line interface")
        .version("1.0")
        .subcommand(
            SubCommand::with_name("license")
                .about("license management")
                .subcommand(
                    SubCommand::with_name("new")
                        .arg(
                            Arg::with_name("POLICY_UUID")
                                .takes_value(true)
                                .index(1)
                                .required(true)
                                .help("UUID of the policy to use for creating the licenses (shortcuts \"STUDIO\", \"INDIE\" and \"COMMUNITY\" are also allowed).")
                        )
                        .arg(Arg::with_name("dry-run").long("dry-run").help("display the contents of API requests to keygen.sh but do not send them"))
                        .arg(
                            Arg::with_name("count")
                                .takes_value(true)
                                .value_name("COUNT")
                                .short("c")
                                .long("count")
                                .help("number of licenses to generate")
                                .default_value("1")
                        )
                        .arg(
                            Arg::with_name("subscription")
                                .long("subscription")
                                .takes_value(true)
                                .value_name("SUBSCRIPTION_ID")
                                .help("FastSpring subscription ID")
                        )
                        .arg(
                            Arg::with_name("invoice")
                                .long("invoice")
                                .takes_value(true)
                                .value_name("INVOICE_ID")
                                .help("invoice identifier")
                        ),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("license") {
        if let Some(matches) = matches.subcommand_matches("new") {
            let subscription_id = matches.value_of("subscription");
            let invoice_id = matches.value_of("invoice");
            let dry_run = matches.is_present("dry-run");
            if let (None, None) = &(subscription_id, invoice_id) {
                eprintln!("error: please specify either a subscription ID or an invoice ID \
                           (with \"--subscription\" or \"--invoice\")");
                return;
            }
            let count = match matches.value_of("count").unwrap().parse::<u32>() {
                Ok(v) if v <= 10 && v > 0 => v,
                Ok(v) if v == 0 => {
                    eprintln!("Please specify a license count greater than 0.");
                    return;
                }
                Ok(_) => {
                    eprintln!("Cannot generate more than 10 licenses at once. \
                                Please specify a license count up to 10 \
                                and run this command multiple times.");
                    return;
                }
                _ => {
                    eprintln!("Invalid number passed to \"--count\" option.\
                                Please specify a number between 1 and 10.");
                    return;
                }
            };

            let policy = matches.value_of("POLICY_UUID").unwrap();
            let (actual_policy, used_policy_shortcut) = match policy {
                "STUDIO" => (POLICY_STUDIO, true),
                "INDIE" => (POLICY_INDIE, true),
                "COMMUNITY" => (POLICY_COMMUNITY, true),
                _ => (policy, false),
            };
            if used_policy_shortcut {
                println!(
                    "Generating {} license(s) with policy {} ({})",
                    count, policy, actual_policy
                );
            } else {
                println!(
                    "Generating {} license(s) with policy {}",
                    count, actual_policy
                );
            }
            println!("    - subscription ID: {}", subscription_id.unwrap_or(""));
            println!("    - invoice ID: {}", invoice_id.unwrap_or(""));

            let (licenses,errors) = generate_licenses(
                subscription_id.unwrap_or(""),
                actual_policy,
                count,
                invoice_id,
                dry_run,
            );
            if !dry_run {
                if !licenses.is_empty() {
                    use clipboard::ClipboardContext;
                    use clipboard::ClipboardProvider;
                    use std::fmt::Write;

                    println!("{} license(s) successfully generated:", licenses.len());
                    let mut all = String::new();
                    for lic in licenses {
                        println!(" - {}", lic);
                        writeln!(all, "{}", lic).unwrap();
                    }

                    let ctx: Result<ClipboardContext, _> = ClipboardProvider::new();
                    if let Ok(mut ctx) = ctx {
                        if let Ok(_) = ctx.set_contents(all) {
                            println!("Licenses copied to clipboard.")
                        }
                    }
                }

                println!();

                if !errors.is_empty() {
                    println!("{} error(s) generating licenses:", errors.len());
                    for err in errors.iter() {
                        println!("    - {}", err);
                    }
                }
            }
        }
    }
}
