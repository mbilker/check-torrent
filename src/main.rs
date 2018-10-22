extern crate rayon;
extern crate serde;
extern crate serde_bencode;
extern crate serde_bytes;
extern crate sha1;

#[macro_use] extern crate serde_derive;

use std::cmp;
use std::env;
use std::fmt::{self, Write};
use std::fs::File as FsFile;
use std::io::{self, Read, Seek, SeekFrom};
use std::mem;
use std::sync::mpsc;

use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde_bencode::de;
use serde_bytes::ByteBuf;
use sha1::Sha1;

fn to_hex_string(data: &[u8]) -> String {
  data.iter().fold(String::with_capacity(data.len() * 2), |mut cur, new| {
    write!(cur, "{:02x}", new);
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
    write!(f, r#"  start: {start},
  end: {end},
  end_type: {end_type:?}
}}"#,
      start = self.start,
      end = self.end,
      end_type = self.end_type)
  }
}

#[derive(Debug, Deserialize)]
struct Node(String, i64);

#[derive(Debug, Deserialize)]
struct File {
  path: Vec<String>,
  length: i64,
  #[serde(default)]
  md5sum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Info {
  name: String,
  pieces: ByteBuf,
  #[serde(rename="piece length")]
  piece_length: i64,
  #[serde(default)]
  md5sum: Option<String>,
  #[serde(default)]
  length: Option<i64>,
  #[serde(default)]
  files: Option<Vec<File>>,
  #[serde(default)]
  private: Option<u8>,
  #[serde(default)]
  path: Option<Vec<String>>,
  #[serde(default)]
  #[serde(rename="root hash")]
  root_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Torrent {
  info: Info,
  #[serde(default)]
  announce: Option<String>,
  #[serde(default)]
  nodes: Option<Vec<Node>>,
  #[serde(default)]
  encoding: Option<String>,
  #[serde(default)]
  httpseeds: Option<Vec<String>>,
  #[serde(default)]
  #[serde(rename="announce-list")]
  announce_list: Option<Vec<Vec<String>>>,
  #[serde(default)]
  #[serde(rename="creation date")]
  creation_date: Option<i64>,
  #[serde(rename="comment")]
  comment: Option<String>,
  #[serde(default)]
  #[serde(rename="created by")]
  created_by: Option<String>,
}

fn compute_piece_hash(files: &[FileIndex]) -> Result<[u8; 20], io::Error> {
  let mut hasher = Sha1::new();

  for FileIndex { path, start, end, .. } in files {
    //println!("path: {:?} (start: {}, end: {})", path, start, end);

    // Offset the read bytes to the start of the part of the file we actually
    // care about
    let mut read_counter = *start;

    let mut fd = FsFile::open(path.join("/"))?;
    if read_counter > 0 {
      fd.seek(SeekFrom::Start(read_counter as u64))?;
    }

    const BUFFER_LENGTH: usize = 64 * 1024;
    let mut buffer = [0; BUFFER_LENGTH];

    loop {
      let request_amount = cmp::min(BUFFER_LENGTH, *end - read_counter);
      let read_amount = fd.read(&mut buffer[..request_amount])?;
      //println!("read (num: {:?}, read_bytes: {:?})", num, read_bytes);

      if read_amount == 0 {
        break;
      }

      if read_counter + read_amount >= *end {
        //println!("hit end (read_bytes: {}, buffer len: {}, read_bytes + buffer len = {})", read_bytes, buffer.len(), read_bytes + buffer.len());
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

  Ok(computed_hash)
}

fn render_torrent(torrent: &Torrent) -> io::Result<()> {
  println!("name:\t\t{}", torrent.info.name);
  println!("announce:\t{:?}", torrent.announce);
  println!("nodes:\t\t{:?}", torrent.nodes);
  if let &Some(ref al) = &torrent.announce_list {
    for a in al {
      println!("announce list:\t{}", a[0]);
    }
  }
  println!("httpseeds:\t{:?}", torrent.httpseeds);
  println!("creation date:\t{:?}", torrent.creation_date);
  println!("comment:\t{:?}", torrent.comment);
  println!("created by:\t{:?}", torrent.created_by);
  println!("encoding:\t{:?}", torrent.encoding);
  println!("piece length:\t{:?}", torrent.info.piece_length);
  println!("private:\t{:?}", torrent.info.private);
  println!("root hash:\t{:?}", torrent.info.root_hash);
  println!("md5sum:\t\t{:?}", torrent.info.md5sum);
  println!("path:\t\t{:?}", torrent.info.path);

  println!("pieces.len(): {}", torrent.info.pieces.len());

  // Each piece is a 160-bit SHA-1 hash
  let count = torrent.info.pieces.chunks(20).count();
  println!("pieces count: {}", count);

  if let &Some(ref files) = &torrent.info.files {
    let piece_size = torrent.info.piece_length as usize;
    println!("piece_size: {}", piece_size);

    // Each piece is a 160-bit SHA-1 hash
    let mut pieces = torrent.info.pieces.chunks(20);

    let mut piece_files = Vec::new();
    let mut current_piece = Vec::new();

    let mut read_bytes = 0;

    for f in files {
      //println!("file path:\t{:?}", f.path);
      //println!("file length:\t{}", f.length);
      //println!("file md5sum:\t{:?}", f.md5sum);

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
          let piece = pieces.next().unwrap();
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

    assert!(!pieces.next().is_some(), "there should be no more pieces");

    let mut all_ok = true;
    let (sender, receiver) = mpsc::channel();

    piece_files
      .par_iter()
      .enumerate()
      .try_for_each_with(sender, |s, (i, (piece, files))| -> Result<(), io::Error> {
        let computed_hash = match compute_piece_hash(files) {
          Ok(v) => v,
          Err(e) => {
            eprintln!("Error processing {:#?}: {:?}", files, e);
            return Err(e);
          },
        };
        if computed_hash != *piece {
          println!("Hash mismatch! (#{}, digest: {:?}, piece: {:?})",
            i,
            to_hex_string(&computed_hash),
            to_hex_string(piece));

          s.send((piece, files, computed_hash)).unwrap();
        } else {
          println!("Hash correct for piece #{} ({})", i, to_hex_string(piece));
        }
        Ok(())
      })
      .unwrap();

    for (piece, files, computed_hash) in receiver {
      eprintln!("Hash mismatch!");
      eprintln!(" - Files:");
      for file in files {
        eprintln!("   - {} (start: {}, end: {}, type: {:?})", file.path.join("/"), file.start, file.end, file.end_type);
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
  }

  Ok(())
}

fn main() -> io::Result<()> {
  if let Some(arg1) = env::args().nth(1) {
    let mut buffer = Vec::new();
    let mut fd = FsFile::open(arg1)?;
    fd.read_to_end(&mut buffer)?;

    match de::from_bytes::<Torrent>(&buffer) {
      Ok(t) => render_torrent(&t)?,
      Err(e) => eprintln!("Error parsing torrent file: {:?}", e),
    };
  }

  Ok(())
}
