// BTC Transaction CLI

use btc_tx_parser::Transaction;
use clap::{Parser, ValueEnum};
use colored::Colorize;
use std::io::{self, Read};

#[derive(Parser)]
#[command(name = "btc-tx-inspector")]
#[command(author = "Bitcoin Transaction Visualizer Contributors")]
#[command(version)]
#[command(about = "Parse and inspect raw Bitcoin transactions")]
struct Cli {
    #[arg(value_name = "TX_HEX")]
    tx_hex: Option<String>, // Transaction hex input

    #[arg(short, long, value_name = "FILE")]
    file: Option<String>, // File input option

    #[arg(short, long, value_enum, default_value = "pretty")]
    output: OutputFormat,

    #[arg(long)]
    raw_scripts: bool,

    #[arg(long)]
    compact: bool,

    #[arg(long, value_delimiter = ',')]
    input_values: Option<Vec<u64>>, // Input values for fee calculation
}

// Output formats
#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
    Summary,
    Ascii,
}


fn main() {
    let cli = Cli::parse();

    let tx_hex = match get_tx_hex(&cli) {
        Ok(hex) => hex,
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            std::process::exit(1);
        }
    };

    let mut tx = match Transaction::from_hex(&tx_hex) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("{}: Failed to parse transaction", "Error".red().bold());
            eprintln!("  {}", e);
            std::process::exit(1);
        }
    };

    if let Some(values) = &cli.input_values {
        if values.len() != tx.inputs.len() {
            eprintln!(
                "{}: Provided {} input values but transaction has {} inputs",
                "Warning".yellow().bold(),
                values.len(),
                tx.inputs.len()
            );
        }
        for (i, &value) in values.iter().enumerate() {
            if i < tx.inputs.len() {
                tx.inputs[i].value = Some(value);
            }
        }
        if let Some(fee) = tx.calculate_fee() {
            tx.fee_satoshis = Some(fee);
            tx.fee_btc = Some(Transaction::satoshis_to_btc(fee));
        }
    }

    match cli.output {
        OutputFormat::Pretty => print_pretty(&tx),
        OutputFormat::Json => print_json(&tx, cli.compact),
        OutputFormat::Summary => print_summary(&tx),
        OutputFormat::Ascii => print_ascii(&tx),
    }
}

//transaction hex from CLI, file, or stdin
fn get_tx_hex(cli: &Cli) -> Result<String, String> {
    if let Some(file_path) = &cli.file {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file '{}': {}", file_path, e))?;
        return Ok(content.trim().to_string());
    }

    match &cli.tx_hex {
        Some(hex) if hex == "-" => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| format!("Failed to read from stdin: {}", e))?;
            Ok(buffer.trim().to_string())
        }
        Some(hex) => Ok(hex.trim().to_string()),
        None => {
            if atty::is(atty::Stream::Stdin) {
                Err("No transaction provided. Use -h for help.".to_string())
            } else {
                let mut buffer = String::new();
                io::stdin()
                    .read_to_string(&mut buffer)
                    .map_err(|e| format!("Failed to read from stdin: {}", e))?;
                Ok(buffer.trim().to_string())
            }
        }
    }
}

//output
fn print_pretty(tx: &Transaction) {
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".bright_blue());
    println!("{}", "                    BITCOIN TRANSACTION".bright_blue().bold());
    println!("{}", "═══════════════════════════════════════════════════════════════".bright_blue());
    println!();

    println!("{}", "Transaction Info".cyan().bold());
    println!("  {} {}", "TXID:".white().bold(), tx.txid.yellow());
    if tx.is_segwit {
        println!("  {} {}", "WTXID:".white().bold(), tx.wtxid.yellow());
    }
    println!("  {} {}", "Version:".white().bold(), tx.version);
    println!("  {} {}", "SegWit:".white().bold(), if tx.is_segwit { "Yes".green() } else { "No".white() });
    println!("  {} {} bytes", "Size:".white().bold(), tx.raw_size);
    println!("  {} {} vbytes", "Virtual Size:".white().bold(), tx.vsize());
    println!("  {} {} WU", "Weight:".white().bold(), tx.weight);
    println!("  {} {}", "Locktime:".white().bold(), format_locktime(tx.locktime));
    println!();

    println!("{} ({})", "Inputs".cyan().bold(), tx.inputs.len());
    println!("{}", "─".repeat(60).bright_black());
    for input in &tx.inputs {
        println!("  {} #{}", "Input".white().bold(), input.index);
        if input.is_coinbase {
            println!("    {} {}", "Type:".white(), "Coinbase".magenta().bold());
        } else {
            println!("    {} {}:{}", "Spends:".white(), input.txid.yellow(), input.vout);
        }
        if let Some(value) = input.value {
            println!("    {} {} sats ({:.8} BTC)", 
                "Value:".white(), 
                value.to_string().green(),
                Transaction::satoshis_to_btc(value)
            );
        }
        println!("    {} 0x{:08x}", "Sequence:".white(), input.sequence);
        if !input.script_sig.hex.is_empty() {
            println!("    {} {} bytes", "ScriptSig:".white(), input.script_sig.size);
            if input.script_sig.asm.len() < 100 {
                println!("      {}", input.script_sig.asm.bright_black());
            }
        }
        if let Some(witness) = &input.witness {
            println!("    {} {} items", "Witness:".white(), witness.len());
            for (i, item) in witness.iter().enumerate() {
                if item.len() < 100 {
                    println!("      [{}] {}", i, item.bright_black());
                } else {
                    println!("      [{}] {}...", i, &item[..64].bright_black());
                }
            }
        }
        println!();
    }

    println!("{} ({})", "Outputs".cyan().bold(), tx.outputs.len());
    println!("{}", "─".repeat(60).bright_black());
    for output in &tx.outputs {
        println!("  {} #{}", "Output".white().bold(), output.index);
        println!("    {} {} sats ({:.8} BTC)", 
            "Value:".white(), 
            output.value.to_string().green().bold(),
            output.value_btc
        );
        println!("    {} {}", "Type:".white(), format!("{}", output.script_type).cyan());
        if let Some(addr) = &output.address {
            println!("    {} {}", "Address:".white(), addr.mainnet.yellow());
            println!("    {} {}", "Testnet:".white(), addr.testnet.bright_black());
        }
        println!("    {} {} bytes", "Script:".white(), output.script_pubkey.size);
        if output.script_pubkey.asm.len() < 100 {
            println!("      {}", output.script_pubkey.asm.bright_black());
        }
        println!();
    }

    println!("{}", "Summary".cyan().bold());
    println!("{}", "─".repeat(60).bright_black());
    println!("  {} {} sats ({:.8} BTC)", 
        "Total Output:".white().bold(),
        tx.total_output_satoshis.to_string().green(),
        tx.total_output_btc
    );
    if let Some(fee) = tx.fee_satoshis {
        println!("  {} {} sats ({:.8} BTC)", 
            "Fee:".white().bold(),
            fee.to_string().red(),
            tx.fee_btc.unwrap_or(0.0)
        );
        let fee_rate = fee as f64 / tx.vsize() as f64;
        println!("  {} {:.2} sat/vB", "Fee Rate:".white().bold(), fee_rate);
    }
    println!();
}

// JSON output
fn print_json(tx: &Transaction, compact: bool) {
    let json = if compact {
        serde_json::to_string(tx)
    } else {
        serde_json::to_string_pretty(tx)
    };

    match json {
        Ok(s) => println!("{}", s),
        Err(e) => {
            eprintln!("Error serializing to JSON: {}", e);
            std::process::exit(1);
        }
    }
}

// Human-readable summary
fn print_summary(tx: &Transaction) {
    println!("Transaction: {}", tx.txid);
    println!("  Version: {}, SegWit: {}", tx.version, tx.is_segwit);
    println!("  {} input(s), {} output(s)", tx.inputs.len(), tx.outputs.len());
    println!("  Size: {} bytes, vSize: {} vbytes", tx.raw_size, tx.vsize());
    println!("  Total output: {:.8} BTC ({} sats)", tx.total_output_btc, tx.total_output_satoshis);
    
    if let Some(fee) = tx.fee_satoshis {
        println!("  Fee: {:.8} BTC ({} sats)", tx.fee_btc.unwrap_or(0.0), fee);
    }

    println!("\nOutputs:");
    for output in &tx.outputs {
        let addr = output.address.as_ref()
            .map(|a| a.mainnet.clone())
            .unwrap_or_else(|| "[non-standard]".to_string());
        println!("  #{}: {:.8} BTC -> {} ({})", 
            output.index, 
            output.value_btc, 
            addr,
            output.script_type
        );
    }
}

// ASCII art visualization
fn print_ascii(tx: &Transaction) {
    println!();
    println!("┌─────────────────────────────────────────────────────────────────────┐");
    println!("│ TX: {}...{} │", &tx.txid[..16], &tx.txid[tx.txid.len()-8..]);
    println!("├─────────────────────────────────────────────────────────────────────┤");
    
    let input_count = tx.inputs.len();
    let output_count = tx.outputs.len();
    let max_rows = input_count.max(output_count);

    for i in 0..max_rows {
        let input_str = if i < input_count {
            let input = &tx.inputs[i];
            if input.is_coinbase {
                format!("  [COINBASE]")
            } else {
                let value_str = input.value
                    .map(|v| format!("{:.4} BTC", Transaction::satoshis_to_btc(v)))
                    .unwrap_or_else(|| "? BTC".to_string());
                format!("  {}:{} ({})", &input.txid[..8], input.vout, value_str)
            }
        } else {
            String::new()
        };

        let output_str = if i < output_count {
            let output = &tx.outputs[i];
            let addr = output.address.as_ref()
                .map(|a| if a.mainnet.len() > 20 { 
                    format!("{}...", &a.mainnet[..20]) 
                } else { 
                    a.mainnet.clone() 
                })
                .unwrap_or_else(|| "[script]".to_string());
            format!("{:.4} BTC -> {}", output.value_btc, addr)
        } else {
            String::new()
        };

        let arrow = if i == max_rows / 2 { "═══►" } else { "    " };
        
        println!("│ {:30} {} {:34} │", 
            if input_str.len() > 30 { format!("{}...", &input_str[..27]) } else { input_str },
            arrow,
            if output_str.len() > 34 { format!("{}...", &output_str[..31]) } else { output_str }
        );
    }

    println!("├─────────────────────────────────────────────────────────────────────┤");
    
    let total = format!("Total: {:.8} BTC", tx.total_output_btc);
    let fee = tx.fee_satoshis
        .map(|f| format!(" | Fee: {} sats", f))
        .unwrap_or_default();
    
    println!("│ {:<67} │", format!("{}{}", total, fee));
    println!("└─────────────────────────────────────────────────────────────────────┘");
    println!();
}

// Format locktime for display
fn format_locktime(locktime: u32) -> String {
    if locktime == 0 {
        "0 (no lock)".to_string()
    } else if locktime < 500_000_000 {
        format!("{} (block height)", locktime)
    } else {
        let datetime = chrono::DateTime::from_timestamp(locktime as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "invalid timestamp".to_string());
        format!("{} ({})", locktime, datetime)
    }
}
