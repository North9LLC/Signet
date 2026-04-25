// signet-fsk CLI. Four subcommands:
//   generate <out.wav> [--sig <hex>]   encode beacon into a WAV file
//   decode <in.wav>                    decode a WAV file and print the payload
//   roundtrip                          in-memory encode + decode smoke test
//   sweep                              BER matrix across SNR / bandpass / reverb

use signet_fsk_proto::{channel, drand, modem, payload, wav};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn usage() -> ! {
    eprintln!("usage: signet-fsk <generate|decode|roundtrip|sweep> [args...]");
    eprintln!();
    eprintln!("  generate <out.wav> [--sig <hex>]");
    eprintln!("      Encode a beacon. --sig uses a fixed 192-hex signature;");
    eprintln!("      otherwise fetches the current drand round.");
    eprintln!();
    eprintln!("  decode <in.wav>");
    eprintln!("      Decode a WAV file and print the recovered 16-byte payload.");
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
                println!("  round={} sig_len={}", r.round, r.signature_hex.len());
                r.signature_hex
            }
            Err(e) => {
                eprintln!("drand fetch failed: {}", e);
                std::process::exit(1);
            }
        }
    };

    let pay = payload::derive_from_drand_signature(&sig_hex);
    println!("payload: {}", hex(&pay));

    let samples = modem::encode(&pay);
    let w = wav::Wav {
        sample_rate: modem::SAMPLE_RATE,
        samples,
    };
    w.write(out_path).expect("write wav");
    println!("wrote {} ({} samples, {:.0} ms)",
        out_path,
        w.samples.len(),
        1000.0 * w.samples.len() as f32 / modem::SAMPLE_RATE as f32);
}

fn cmd_decode(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let w = wav::Wav::read(&args[0]).expect("read wav");
    if w.sample_rate != modem::SAMPLE_RATE {
        eprintln!("warning: sample rate {} != expected {}", w.sample_rate, modem::SAMPLE_RATE);
    }
    match modem::decode(&w.samples) {
        Ok(p) => {
            println!("ok: {}", hex(&p));
        }
        Err(e) => {
            eprintln!("decode failed: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_roundtrip() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut pay = [0u8; 16];
    rng.fill_bytes(&mut pay);
    let sig = modem::encode(&pay);
    match modem::decode(&sig) {
        Ok(r) if r == pay => println!("ok: roundtrip matches: {}", hex(&pay)),
        Ok(r) => {
            eprintln!("MISMATCH: sent {} recv {}", hex(&pay), hex(&r));
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("decode failed: {:?}", e);
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
            let mut pay = [0u8; 16];
            rng.fill_bytes(&mut pay);
            let s = modem::encode(&pay);
            let y = channel::apply(&s, &cfg, &mut rng);
            if let Ok(r) = modem::decode(&y) {
                if r == pay {
                    ok += 1;
                }
            }
        }
        println!("  {:<46} |  {:>3}/{:<3}  |", label, ok, TRIALS);
    }
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
        "roundtrip" => cmd_roundtrip(),
        "sweep" => cmd_sweep(),
        _ => usage(),
    }
}
