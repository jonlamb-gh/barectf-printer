use anyhow::anyhow;
use barectf_parser::{
    Config as BarectfConfig, Error, Event, FieldValue, PacketContext, PacketHeader,
    Parser as BarectfParser, PreferredDisplayBase, PrimitiveFieldValue,
};
use clap::Parser as ClapParser;
use std::{
    fs::{self, File},
    io::{self, BufReader},
    path::PathBuf,
};
use tracing::{error, info};

// TODO opts
// for showing packet context fields (seqnum/etc)
// timestamp conversion: --clock-cycles, etc
//
#[derive(clap::Parser, Debug, Clone)]
#[clap(version, about = "Print barectf-generated CTF trace data from file", long_about = None)]
pub struct Opts {
    /// The barectf effective-configuration yaml file
    pub config: PathBuf,

    /// The binary CTF stream(s) file.
    ///
    /// Can be supplied multiple times.
    pub stream: Vec<PathBuf>,
}

fn main() {
    match do_main() {
        Ok(()) => (),
        Err(e) => {
            eprintln!("{e}");
            let mut cause = e.source();
            while let Some(err) = cause {
                eprintln!("Caused by: {err}");
                cause = err.source();
            }
            std::process::exit(exitcode::SOFTWARE);
        }
    }
}

fn do_main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();

    reset_signal_pipe_handler()?;

    tracing_subscriber::fmt::init();

    info!(config = %opts.config.display(), "Reading effective configuration file");
    let cfg_content = fs::read_to_string(&opts.config).map_err(|e| {
        anyhow!(
            "Failed to open barectf effective-configuration yaml file '{}'. {}",
            opts.config.display(),
            e
        )
    })?;
    let cfg: BarectfConfig = serde_yaml::from_str(&cfg_content).map_err(|e| {
        anyhow!(
            "Failed to parse barectf effective-configuration yaml file '{}'. {}",
            opts.config.display(),
            e
        )
    })?;

    if opts.stream.is_empty() {
        return Err(anyhow!(
            "Missing CTF stream file(s). Specify a path to import on the command line."
        )
        .into());
    }

    let parser = BarectfParser::new(&cfg)?;

    for stream_path in opts.stream.iter() {
        info!(file = %stream_path.display(), "Opening CTF stream");

        let stream = File::open(stream_path).map_err(|e| {
            anyhow!(
                "Failed to open stream file '{}'. {}",
                stream_path.display(),
                e
            )
        })?;

        let mut reader = BufReader::new(stream);

        'events: loop {
            let pkt = match parser.parse(&mut reader) {
                Ok(p) => p,
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    break 'events;
                }
                Err(e) => {
                    error!("{e}");
                    break 'events;
                }
            };

            for event in pkt.events.iter() {
                print_event(event, &pkt.header, &pkt.context);
            }
        }
    }

    Ok(())
}

// Used to prevent panics on broken pipes.
// See:
//   https://github.com/rust-lang/rust/issues/46016#issuecomment-605624865
fn reset_signal_pipe_handler() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_family = "unix")]
    {
        use nix::sys::signal;

        unsafe {
            signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigDfl)?;
        }
    }

    Ok(())
}

fn print_event(event: &Event, pkt_hdr: &PacketHeader, pkt_ctx: &PacketContext) {
    let pc = if pkt_ctx.extra_members.is_empty() {
        "".to_owned()
    } else {
        let inner = pkt_ctx
            .extra_members
            .iter()
            .map(|(n, v)| format!("{} = {}", n, fmt_fv(v)))
            .collect::<Vec<String>>()
            .join(", ");
        format!("{{ {} }}", inner)
    };

    let cc = if event.common_context.is_empty() {
        "".to_owned()
    } else {
        let inner = event
            .common_context
            .iter()
            .map(|(n, v)| format!("{} = {}", n, fmt_fv(v)))
            .collect::<Vec<String>>()
            .join(", ");
        format!("{{ {} }}", inner)
    };

    let sp = if event.specific_context.is_empty() {
        "".to_owned()
    } else {
        let inner = event
            .specific_context
            .iter()
            .map(|(n, v)| format!("{} = {}", n, fmt_fv(v)))
            .collect::<Vec<String>>()
            .join(", ");
        format!("{{ {} }}", inner)
    };

    let pl = if event.payload.is_empty() {
        "".to_owned()
    } else {
        let inner = event
            .payload
            .iter()
            .map(|(n, v)| format!("{} = {}", n, fmt_fv(v)))
            .collect::<Vec<String>>()
            .join(", ");
        format!("{{ {} }}", inner)
    };

    let content = [pc, cc, sp, pl]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<String>>()
        .join(", ");

    print!("[{:016}]", event.timestamp);
    print!(" {} @ {}:", event.name, pkt_hdr.stream_name);
    print!(" {}", content);
    println!();
}

fn fmt_fv(fv: &FieldValue) -> String {
    match fv {
        FieldValue::Primitive(p) => fmt_pfv(p),
        FieldValue::Array(arr) => {
            let inner = arr
                .iter()
                .enumerate()
                .map(|(idx, pfv)| format!("[{}] = {}", idx, fmt_pfv(pfv)))
                .collect::<Vec<String>>()
                .join(", ");
            format!("[ {} ]", inner)
        }
    }
}

fn fmt_pfv(pfv: &PrimitiveFieldValue) -> String {
    match pfv {
        PrimitiveFieldValue::UnsignedInteger(v, pdb) => match pdb {
            PreferredDisplayBase::Binary => format!("{v:#b}"),
            PreferredDisplayBase::Octal => format!("{v:#o}"),
            PreferredDisplayBase::Decimal => format!("{v}"),
            PreferredDisplayBase::Hexadecimal => format!("{v:#X}"),
        },
        PrimitiveFieldValue::SignedInteger(v, pdb) => match pdb {
            PreferredDisplayBase::Binary => format!("{v:#b}"),
            PreferredDisplayBase::Octal => format!("{v:#o}"),
            PreferredDisplayBase::Decimal => format!("{v}"),
            PreferredDisplayBase::Hexadecimal => format!("{v:#X}"),
        },
        PrimitiveFieldValue::String(v) => format!("\"{v}\""),
        PrimitiveFieldValue::F32(v) => format!("{:03}", v.0),
        PrimitiveFieldValue::F64(v) => format!("{:03}", v.0),
        PrimitiveFieldValue::Enumeration(v, pdb, maybe_label) => {
            let container = match pdb {
                PreferredDisplayBase::Binary => format!("{v:#b}"),
                PreferredDisplayBase::Octal => format!("{v:#o}"),
                PreferredDisplayBase::Decimal => format!("{v}"),
                PreferredDisplayBase::Hexadecimal => format!("{v:#X}"),
            };
            if let Some(label) = maybe_label {
                format!("( \"{label}\" : container = {container} )")
            } else {
                format!("( container = {container} )")
            }
        }
    }
}
