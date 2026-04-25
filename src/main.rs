// signet CLI. Subcommands:
//   generate <out.wav> [--sig <hex>]        encode beacon into a WAV file
//   decode <in.wav> [--json]                decode a WAV file and print the payload
//   verify <in.wav> [--round <N>] [--json]  decode and verify against drand
//   roundtrip                               in-memory encode + decode smoke test
//   sweep                                   BER matrix across SNR / bandpass / reverb

use signet::{channel, drand, fec, modem, payload, wav};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn usage() -> ! {
    eprintln!("usage: signet <generate|decode|verify|roundtrip|sweep> [args...]");
    eprintln!();
    eprintln!("  generate <out.wav> [--sig <hex>]");
    eprintln!("      Encode a beacon. --sig uses a fixed 192-hex signature;");
    eprintln!("      otherwise fetches the current drand round.");
    eprintln!();
    eprintln!("  decode <in.wav> [--json]");
    eprintln!("      Decode a WAV file and print the recovered 16-byte payload.");
    eprintln!("      --json outputs {{\"ok\":true,\"payload\":\"hex\",\"round_hint\":null}}");
    eprintln!();
    eprintln!("  verify <in.wav> [--round <N>] [--json]");
    eprintln!("      Decode and verify against the drand chain.");
    eprintln!("      --round N: verify against a specific round.");
    eprintln!("      Without --round: tries latest round and ±5 rounds (30s window each).");
    eprintln!("      --json outputs {{\"verified\":true/false,\"round\":N,\"time\":\"...\",\"error\":\"...\"}}");
    eprintln!();
    eprintln!("  roundtrip");
    eprintln!("      In-memory encode+decode with a random payload.");
    eprintln!();
    eprintln!("  sweep");
    eprintln!("      Run a BER matrix across SNR / bandpass / reverb.");
    std::process::exit(2);
}

fn cmd_generate(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let out_path = &args[0];
    let sig_hex = if let Some(pos) = args.iter().position(|a| a == "--sig") {
        args.get(pos + 1).cloned().unwrap_or_else(|| {
            eprintln!("--sig requires a value");
            std::process::exit(2);
        })
    } else {
        println!("fetching latest drand round...");
        match drand::fetch_latest() {
            Ok(r) => {
                let ts = drand::round_to_unix(r.round);
                println!("  round={} time={} sig_len={}",
                    r.round,
                    unix_to_utc(ts),
                    r.signature_hex.len());
                r.signature_hex
            }
            Err(e) => {
                eprintln!("drand fetch failed: {}", e);
                std::process::exit(1);
            }
        }
    };

    let pay16 = match payload::derive_from_drand_signature(&sig_hex) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("payload derivation failed: {}", e);
            std::process::exit(1);
        }
    };
    println!("payload (16 bytes): {}", hex(&pay16));

    let pay20 = fec::rs_encode(&pay16);
    println!("encoded (20 bytes): {}", hex(&pay20));

    let samples = modem::encode(&pay20);
    let w = wav::Wav {
        sample_rate: modem::SAMPLE_RATE,
        samples,
    };
    if let Err(e) = w.write(out_path) {
        eprintln!("write wav failed: {}", e);
        std::process::exit(1);
    }
    println!("wrote {} ({} samples, {:.0} ms)",
        out_path,
        w.samples.len(),
        1000.0 * w.samples.len() as f32 / modem::SAMPLE_RATE as f32);
}

fn cmd_decode(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let json_mode = args.iter().any(|a| a == "--json");
    let in_path = &args[0];

    let w = match wav::Wav::read(in_path) {
        Ok(w) => w,
        Err(e) => {
            if json_mode {
                println!("{{\"ok\":false,\"error\":\"read wav failed: {}\"}}", e);
            } else {
                eprintln!("read wav failed: {}", e);
            }
            std::process::exit(1);
        }
    };
    if w.sample_rate != modem::SAMPLE_RATE {
        eprintln!("warning: sample rate {} != expected {}", w.sample_rate, modem::SAMPLE_RATE);
    }

    let raw20 = match modem::decode(&w.samples) {
        Ok(p) => p,
        Err(e) => {
            if json_mode {
                println!("{{\"ok\":false,\"error\":\"modem decode failed: {:?}\"}}", e);
            } else {
                eprintln!("modem decode failed: {:?}", e);
            }
            std::process::exit(1);
        }
    };

    match fec::rs_decode(&raw20) {
        Some(pay16) => {
            if json_mode {
                println!("{{\"ok\":true,\"payload\":\"{}\",\"round_hint\":null}}", hex(&pay16));
            } else {
                println!("ok: {}", hex(&pay16));
            }
        }
        None => {
            if json_mode {
                println!("{{\"ok\":false,\"error\":\"FEC: uncorrectable\"}}");
            } else {
                eprintln!("FEC: uncorrectable");
            }
            std::process::exit(1);
        }
    }
}

fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let json_mode = args.iter().any(|a| a == "--json");
    let in_path = &args[0];

    // Parse --round
    let specific_round: Option<u64> = if let Some(pos) = args.iter().position(|a| a == "--round") {
        match args.get(pos + 1).and_then(|s| s.parse::<u64>().ok()) {
            Some(n) => Some(n),
            None => {
                if json_mode {
                    println!("{{\"verified\":false,\"error\":\"--round requires a number\"}}");
                } else {
                    eprintln!("--round requires a number");
                }
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    // Decode WAV
    let w = match wav::Wav::read(in_path) {
        Ok(w) => w,
        Err(e) => {
            if json_mode {
                println!("{{\"verified\":false,\"error\":\"read wav failed: {}\"}}", e);
            } else {
                eprintln!("read wav failed: {}", e);
            }
            std::process::exit(1);
        }
    };
    if w.sample_rate != modem::SAMPLE_RATE {
        eprintln!("warning: sample rate {} != expected {}", w.sample_rate, modem::SAMPLE_RATE);
    }

    let raw20 = match modem::decode(&w.samples) {
        Ok(p) => p,
        Err(e) => {
            if json_mode {
                println!("{{\"verified\":false,\"error\":\"modem decode failed: {:?}\"}}", e);
            } else {
                eprintln!("modem decode failed: {:?}", e);
            }
            std::process::exit(1);
        }
    };

    let decoded_pay = match fec::rs_decode(&raw20) {
        Some(p) => p,
        None => {
            if json_mode {
                println!("{{\"verified\":false,\"error\":\"FEC: uncorrectable\"}}");
            } else {
                eprintln!("FEC: uncorrectable");
            }
            std::process::exit(1);
        }
    };

    // Build list of rounds to try
    let rounds_to_try: Vec<u64> = if let Some(r) = specific_round {
        vec![r]
    } else {
        // Fetch latest round and try ±5 rounds
        match drand::fetch_latest() {
            Ok(latest) => {
                let base = latest.round;
                let mut rounds = Vec::new();
                for delta in -5i64..=5 {
                    let r = base as i64 + delta;
                    if r > 0 {
                        rounds.push(r as u64);
                    }
                }
                rounds
            }
            Err(e) => {
                if json_mode {
                    println!("{{\"verified\":false,\"error\":\"drand fetch failed: {}\"}}", e);
                } else {
                    eprintln!("drand fetch failed: {}", e);
                }
                std::process::exit(1);
            }
        }
    };

    // Try each round
    for round_num in rounds_to_try {
        let round_data = match drand::fetch_round(round_num) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let expected_pay = match payload::derive_from_drand_signature(&round_data.signature_hex) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if expected_pay == decoded_pay {
            let ts = drand::round_to_unix(round_num);
            if json_mode {
                println!("{{\"verified\":true,\"round\":{},\"time\":\"{}\"}}",
                    round_num, unix_to_utc(ts));
            } else {
                println!("verified: round={} time={} UTC", round_num, unix_to_utc(ts));
            }
            return;
        }
    }

    // No match found
    if json_mode {
        println!("{{\"verified\":false,\"error\":\"no matching round found in window\"}}");
    } else {
        println!("no matching round found in window");
    }
    std::process::exit(1);
}

fn cmd_roundtrip() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut pay16 = [0u8; 16];
    rng.fill_bytes(&mut pay16);
    let pay20 = fec::rs_encode(&pay16);
    let sig = modem::encode(&pay20);
    match modem::decode(&sig) {
        Ok(raw20) => match fec::rs_decode(&raw20) {
            Some(r) if r == pay16 => println!("ok: roundtrip matches: {}", hex(&pay16)),
            Some(r) => {
                eprintln!("MISMATCH after FEC: sent {} recv {}", hex(&pay16), hex(&r));
                std::process::exit(1);
            }
            None => {
                eprintln!("FEC decode failed on clean roundtrip (should not happen)");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("modem decode failed: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_sweep() {
    use rand::{RngCore, SeedableRng};
    const TRIALS: usize = 40;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);

    println!("=== Clean & noise-only sweep ({} trials each) ===", TRIALS);
    println!("     config                                 |  success  |");
    println!("-----------------------------------------------+----------+");

    let configs: Vec<(&str, channel::ChannelCfg)> = vec![
        ("clean (no channel)", channel::ChannelCfg::default()),
        ("AWGN 40 dB SNR", channel::ChannelCfg { snr_db: Some(40.0), ..Default::default() }),
        ("AWGN 30 dB SNR", channel::ChannelCfg { snr_db: Some(30.0), ..Default::default() }),
        ("AWGN 20 dB SNR", channel::ChannelCfg { snr_db: Some(20.0), ..Default::default() }),
        ("AWGN 15 dB SNR", channel::ChannelCfg { snr_db: Some(15.0), ..Default::default() }),
        ("AWGN 10 dB SNR", channel::ChannelCfg { snr_db: Some(10.0), ..Default::default() }),
        ("AWGN  5 dB SNR", channel::ChannelCfg { snr_db: Some(5.0),  ..Default::default() }),
        ("AWGN  0 dB SNR", channel::ChannelCfg { snr_db: Some(0.0),  ..Default::default() }),
        ("BP 17-20 kHz + 20 dB SNR", channel::ChannelCfg {
            snr_db: Some(20.0), bandpass: Some((17000.0, 20000.0)), reverb_rt60_ms: None,
        }),
        ("BP 17-20 kHz + 10 dB SNR", channel::ChannelCfg {
            snr_db: Some(10.0), bandpass: Some((17000.0, 20000.0)), reverb_rt60_ms: None,
        }),
        ("reverb  10 ms (tiny room) + 20 dB",  channel::ChannelCfg {
            snr_db: Some(20.0), bandpass: None, reverb_rt60_ms: Some(10.0),
        }),
        ("reverb  30 ms (small room) + 20 dB", channel::ChannelCfg {
            snr_db: Some(20.0), bandpass: None, reverb_rt60_ms: Some(30.0),
        }),
        ("reverb  60 ms + 20 dB",              channel::ChannelCfg {
            snr_db: Some(20.0), bandpass: None, reverb_rt60_ms: Some(60.0),
        }),
        ("reverb 100 ms (typical room) + 20 dB", channel::ChannelCfg {
            snr_db: Some(20.0), bandpass: None, reverb_rt60_ms: Some(100.0),
        }),
        ("reverb 300 ms (hallway) + 20 dB",     channel::ChannelCfg {
            snr_db: Some(20.0), bandpass: None, reverb_rt60_ms: Some(300.0),
        }),
        ("FULL: BP + 15 dB + 30 ms reverb",     channel::ChannelCfg {
            snr_db: Some(15.0), bandpass: Some((17000.0, 20000.0)), reverb_rt60_ms: Some(30.0),
        }),
        ("FULL: BP + 15 dB + 100 ms reverb",    channel::ChannelCfg {
            snr_db: Some(15.0), bandpass: Some((17000.0, 20000.0)), reverb_rt60_ms: Some(100.0),
        }),
    ];

    for (label, cfg) in configs {
        let mut ok = 0;
        for _ in 0..TRIALS {
            let mut pay16 = [0u8; 16];
            rng.fill_bytes(&mut pay16);
            let pay20 = fec::rs_encode(&pay16);
            let s = modem::encode(&pay20);
            let y = channel::apply(&s, &cfg, &mut rng);
            if let Ok(raw20) = modem::decode(&y) {
                if let Some(r) = fec::rs_decode(&raw20) {
                    if r == pay16 {
                        ok += 1;
                    }
                }
            }
        }
        println!("  {:<46} |  {:>3}/{:<3}  |", label, ok, TRIALS);
    }
}

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS".
fn unix_to_utc(ts: u64) -> String {
    // Days since Unix epoch
    let secs = ts % 86400;
    let days = ts / 86400;

    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;

    // Gregorian calendar computation (post-1970 only)
    let (year, month, day) = days_to_ymd(days);

    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hh, mm, ss)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm: convert days since 1970-01-01 to (year, month, day).
    // Use the "civil" algorithm (Howard Hinnant).
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u64, m, d)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        usage();
    }
    let args: Vec<String> = argv.iter().skip(2).cloned().collect();
    match argv[1].as_str() {
        "generate" => cmd_generate(&args),
        "decode" => cmd_decode(&args),
        "verify" => cmd_verify(&args),
        "roundtrip" => cmd_roundtrip(),
        "sweep" => cmd_sweep(),
        _ => usage(),
    }
}
