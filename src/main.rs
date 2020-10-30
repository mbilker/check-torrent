#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate serde_derive;

use std::cmp;
use std::ffi::OsStr;
use std::fmt::{self, Write};
use std::fs::{self, File as FsFile};
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::path::Component;
use std::sync::mpsc;

use anyhow::{Context, Result};
use clap::{App, Arg};
use indicatif::ProgressBar;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde_bencode::de;
use serde_bytes::ByteBuf;
use sha1::Sha1;
use walkdir::{DirEntry, WalkDir};

fn to_hex_string(data: &[u8]) -> String {
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut cur, new| {
            write!(cur, "{:02x}", new).unwrap();
            cur
        })
}

#[derive(Debug)]
enum PieceFileType {
    Whole,
    Partial,
}

struct FileIndex<'a> {
    path: &'a [String],
    start: usize,
    end: usize,
    end_type: PieceFileType,
}

impl<'a> fmt::Debug for FileIndex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "FileIndex {{")?;
        write!(f, "  path: ")?;
        for (i, part) in self.path.iter().enumerate() {
            if i != 0 {
                f.write_str("/")?;
            }
            f.write_str(part)?;
        }
        writeln!(f, ",")?;
        write!(
            f,
            r#"  start: {start},
  end: {end},
  end_type: {end_type:?}
}}"#,
            start = self.start,
            end = self.end,
            end_type = self.end_type
        )
    }
}

#[derive(Deserialize)]
struct File {
    path: Vec<String>,
    length: i64,
}

#[derive(Deserialize)]
struct Info {
    name: String,
    pieces: ByteBuf,
    #[serde(rename = "piece length")]
    piece_length: i64,
    #[serde(default)]
    files: Option<Vec<File>>,
    #[serde(default)]
    private: Option<u8>,
    #[serde(default)]
    path: Option<Vec<String>>,
    #[serde(default, rename = "root hash")]
    root_hash: Option<String>,
}

#[derive(Deserialize)]
struct Torrent {
    info: Info,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default, rename = "creation date")]
    creation_date: Option<i64>,
    #[serde(rename = "comment")]
    comment: Option<String>,
    #[serde(default, rename = "created by")]
    created_by: Option<String>,
}

fn compute_piece_hash<'a>(files: &[FileIndex<'a>]) -> Result<[u8; 20]> {
    const BUFFER_LENGTH: usize = 64 * 1024;

    let mut buffer = [0; BUFFER_LENGTH];
    let mut hasher = Sha1::new();

    for file in files {
        let FileIndex {
            path, start, end, ..
        } = file;

        // Offset the read bytes to the start of the part of the file we actually
        // care about
        let mut read_counter = *start;

        let path = path.join("/");
        let mut fd = FsFile::open(&path).with_context(|| format!("Failed to open '{}'", path))?;
        if read_counter > 0 {
            fd.seek(SeekFrom::Start(read_counter as u64))
                .with_context(|| format!("Failed to seek to {} in '{}'", read_counter, path))?;
        }

        while read_counter < *end {
            let request_amount = cmp::min(BUFFER_LENGTH, *end - read_counter);
            let read_amount = fd
                .read(&mut buffer[..request_amount])
                .with_context(|| format!("Failed to read from '{}'", path))?;

            if read_amount == 0 {
                break;
            }

            if read_counter + read_amount >= *end {
                let remaining = end - read_counter;
                hasher.update(&buffer[..remaining]);

                break;
            } else {
                hasher.update(&buffer);

                read_counter += read_amount;
            }
        }
    }

    let digest = hasher.digest();
    let computed_hash = digest.bytes();
    //println!("digest: {:02x?}", digest.bytes());
    //println!("checking {} with {}", to_hex_string(&computed_hash), to_hex_string(piece_hash));

    Ok(digest.into())
}

fn files_existance_check(files: &[File]) -> Result<()> {
    let mut file_errors = Vec::new();

    for f in files {
        let path = f.path.join("/");
        let meta = match fs::metadata(&path) {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                file_errors.push(anyhow!("'{}' is missing", path));
                continue;
            },
            Err(e) => {
                return Err(e).context(format!("Failed to get the metadata of '{}'", path));
            },
        };

        if !meta.is_file() {
            file_errors.push(anyhow!("'{}' is not a file", path));
            continue;
        }

        if meta.len() != f.length as u64 {
            file_errors.push(anyhow!("'{}' is not of size {} bytes", path, f.length));
        }
    }

    if !file_errors.is_empty() {
        println!("File Errors:");
        for err in file_errors {
            println!("{}", err);
        }
        println!();

        Err(anyhow!("Missing files or mismatched file sizes"))
    } else {
        Ok(())
    }
}

fn is_file(entry: &DirEntry) -> bool {
    entry.metadata().unwrap().is_file()
}

fn extra_files_check(files: &[File]) -> Result<()> {
    let walker = WalkDir::new(".")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(is_file);
    let mut extra_files: Vec<_> = walker
        .filter_map(|entry| {
            // Ignore the `Component::CurDir` part, only get the path components
            let components: Vec<_> = entry
                .path()
                .components()
                .filter_map(|component| match component {
                    Component::Normal(s) => Some(s),
                    _ => None,
                })
                .collect();

            let part_of_torrent = files.iter().any(|file| {
                let mut torrent_path = file.path.iter().map(|component| OsStr::new(component));
                let mut entry_path = components.iter().map(|component| *component);

                loop {
                    // While similar to using `Iterator::zip`, this checks that both
                    // iterators return `None` at the same time.
                    let torrent_part = torrent_path.next();
                    let entry_part = entry_path.next();
                    if torrent_part != entry_part {
                        return false;
                    }

                    // Base case of the loop is when both iterators return `None`
                    if torrent_part == None && entry_part == None {
                        break;
                    }
                }

                true
            });

            if part_of_torrent {
                None
            } else {
                Some(entry.path().to_path_buf())
            }
        })
        .collect();

    extra_files.sort();

    if !extra_files.is_empty() {
        println!("Extra Files:");
        for file in extra_files {
            println!("{}", file.as_path().display());
        }
        println!();
    }

    Ok(())
}

fn files_hash_check(files: &[File], piece_size: usize, pieces: &[u8]) -> Result<()> {
    // Each piece is a 160-bit SHA-1 hash
    let mut pieces = pieces.chunks(20);

    let mut piece_files = Vec::new();
    let mut current_piece = Vec::new();

    let mut read_bytes = 0;

    for f in files {
        let file_length = f.length as usize;

        // Check if the file size will fill the current piece
        if read_bytes + file_length < piece_size {
            current_piece.push(FileIndex {
                path: &f.path,
                start: 0,
                end: f.length as usize,
                end_type: PieceFileType::Whole,
            });

            read_bytes += file_length;
        } else {
            let mut start = 0;

            // Determine the number of pieces the current file will occupy,
            // taking into account the remaining size of the current piece
            let remaining = piece_size - read_bytes;
            if remaining > 0 {
                let piece = pieces.next().unwrap();
                //println!("read piece (remaining): {:02x?}", piece);

                current_piece.push(FileIndex {
                    path: &f.path,
                    start: 0,
                    end: remaining,
                    end_type: PieceFileType::Partial,
                });

                start = remaining;

                let files = mem::replace(&mut current_piece, Vec::new());
                piece_files.push((piece, files));
            }

            let num_pieces = (file_length - start) / piece_size;
            for _ in 0..num_pieces {
                let piece = pieces.next().with_context(|| {
                    format!("Piece for '{}' at {} not found", f.path.join("/"), start)
                })?;
                //println!("read piece: {:02x?}", piece);

                let files = vec![FileIndex {
                    path: &f.path,
                    start,
                    end: start + piece_size,
                    end_type: PieceFileType::Partial,
                }];
                piece_files.push((piece, files));

                start += piece_size;
            }

            current_piece.push(FileIndex {
                path: &f.path,
                start,
                end: file_length,
                end_type: PieceFileType::Partial,
            });
            read_bytes = file_length - start;
        }
    }

    if let Some(piece) = pieces.next() {
        let files = mem::replace(&mut current_piece, Vec::new());
        piece_files.push((piece, files));
    }

    if pieces.next().is_some() {
        return Err(anyhow!("There should be no more pieces"));
    }

    let mut all_ok = true;
    let bar = ProgressBar::new(piece_files.len() as u64);
    let (sender, receiver) = mpsc::channel();

    bar.enable_steady_tick(10);

    fn check_handler<'data>(
        sender: &mut mpsc::Sender<(&'data [u8], &'data [FileIndex<'data>], [u8; 20])>,
        bar: &ProgressBar,
        i: usize,
        piece: &'data [u8],
        files: &'data [FileIndex<'data>],
    ) -> Result<()> {
        let computed_hash = match compute_piece_hash(files) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error processing {:#?}: {:?}", files, e);
                return Err(e);
            },
        };

        bar.inc(1);

        if computed_hash != *piece {
            bar.set_message(&format!(
                "Hash mismatch! (#{}, digest: {:?}, piece: {:?})",
                i,
                to_hex_string(&computed_hash),
                to_hex_string(piece)
            ));

            sender.send((piece, files, computed_hash)).unwrap();
        }

        Ok(())
    }

    piece_files
        .par_iter()
        .enumerate()
        .try_for_each_with(sender, |sender, (i, (piece, files))| {
            check_handler(sender, &bar, i, piece, files)
        })?;

    bar.finish_and_clear();

    for (piece, files, computed_hash) in receiver {
        eprintln!("Hash mismatch!");
        eprintln!(" - Files:");
        for file in files {
            eprintln!(
                "   - {} (start: {}, end: {}, type: {:?})",
                file.path.join("/"),
                file.start,
                file.end,
                file.end_type
            );
        }
        eprintln!(" - Torrent piece hash: {}", to_hex_string(piece));
        eprintln!(" - Computed hash:      {}", to_hex_string(&computed_hash));

        all_ok = false;
    }

    if all_ok {
        println!("All pieces are good!");
    } else {
        println!("One or more pieces are invalid");
    }

    Ok(())
}

fn render_torrent(torrent: &Torrent) -> Result<()> {
    // Each piece is a 160-bit SHA-1 hash
    let count = torrent.info.pieces.chunks(20).count();
    println!("piece buffer length: {}", torrent.info.pieces.len());
    println!("pieces count:        {}", count);

    if let &Some(ref files) = &torrent.info.files {
        extra_files_check(files)?;
        files_existance_check(files)?;

        let piece_size = torrent.info.piece_length as usize;
        files_hash_check(files, piece_size, &torrent.info.pieces)?;
    }

    Ok(())
}

fn check_torrent_file(path: &str, should_check: bool) -> Result<()> {
    let buffer = fs::read(path).context("Failed to read torrent file")?;
    let torrent = de::from_bytes::<Torrent>(&buffer)?;

    println!("name:\t\t{}", torrent.info.name);
    println!("creation date:\t{:?}", torrent.creation_date);
    println!("comment:\t{:?}", torrent.comment);
    println!("created by:\t{:?}", torrent.created_by);
    println!("encoding:\t{:?}", torrent.encoding);
    println!("piece length:\t{:?}", torrent.info.piece_length);
    println!("private:\t{:?}", torrent.info.private);
    println!("root hash:\t{:?}", torrent.info.root_hash);
    println!("path:\t\t{:?}", torrent.info.path);

    if should_check {
        render_torrent(&torrent)?;
    }

    Ok(())
}

fn main() {
    #[rustfmt::skip]
    let matches = App::new("Check Torrent")
        .arg(Arg::with_name("no_check")
            .short("n")
            .long("no-check")
            .help("Do not check the piece hashes, only print torrent metadata"))
        .arg(Arg::with_name("file")
            .index(1)
            .required(true))
        .get_matches();

    let should_check = !matches.is_present("no_check");
    let torrent_file = matches.value_of("file").unwrap();

    if let Err(e) = check_torrent_file(torrent_file, should_check) {
        eprintln!("An error occurred while checking '{}':", torrent_file);
        eprintln!("  {:?}", e);
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let _ = Command::new("cmd.exe").arg("/c").arg("pause").status();
    }
}
