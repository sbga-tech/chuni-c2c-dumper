#![allow(dead_code)]

use std::{
    fmt,
    io::{self, Cursor, Read, Write},
    net::Ipv4Addr,
};

use aes::Aes128Dec;
use byteorder::{NetworkEndian, ReadBytesExt, LE};
use chrono::{DateTime, Local};
use cipher::{inout::InOutBuf, BlockDecrypt, KeyInit};
use faster_hex::hex_string;
use num_enum::FromPrimitive;
use tracing::{info, info_span};

trait Parse {
    fn parse<R: Read>(reader: &mut R) -> io::Result<Self>
    where
        Self: Sized;
}

impl Parse for String {
    fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let len = reader.read_u32::<LE>()?;
        let mut buf = vec![0; len as usize];
        reader.read_exact(&mut buf)?;
        String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Parse for Ipv4Addr {
    fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        reader.read_u32::<NetworkEndian>().map(Ipv4Addr::from_bits)
    }
}

struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Parse for Version {
    fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        let ver = reader.read_u32::<LE>()?;
        Ok(Self {
            major: (ver / 1_000_000) as u16,
            minor: ((ver / 1000) % 1000) as u16,
            patch: (ver % 1000) as u16,
        })
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}.{:02}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, FromPrimitive)]
#[repr(u32)]
enum Command {
    Recruit = 11,
    RecruitEnd = 12,
    #[num_enum(catch_all)]
    Unknown(u32),
}

#[derive(Debug)]
struct Header {
    rom_version: Version,
    data_version: Version,
    command: Command,
}

impl Parse for Header {
    fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        Ok(Self {
            rom_version: Version::parse(reader)?,
            data_version: Version::parse(reader)?,
            command: reader.read_u32::<LE>()?.into(),
        })
    }
}

#[derive(Debug)]
struct ArchiveHeader {
    magic: String,
    version: u16,
    size_int: u8,
    size_long: u8,
    size_float: u8,
    size_double: u8,
    endian: u32,
}

impl Parse for ArchiveHeader {
    fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        Ok(Self {
            magic: String::parse(reader)?,
            version: reader.read_u16::<LE>()?,
            size_int: reader.read_u8()?,
            size_long: reader.read_u8()?,
            size_float: reader.read_u8()?,
            size_double: reader.read_u8()?,
            endian: reader.read_u32::<LE>()?,
        })
    }
}

#[derive(Debug, FromPrimitive)]
#[repr(u32)]
enum Group {
    A = 1,
    B = 2,
    C = 3,
    D = 4,
    #[num_enum(catch_all)]
    Unknown(u32),
}

#[derive(Debug)]
struct Recruit {
    flag: bool,
    unknown0: u32,
    host: Ipv4Addr,
    aime_id: u32,
    name: String,
    chara: u32,
    chara_level: u32,
    skill: u32,
    skill_level: u32,
    trophy: u32,
    trophy2: u32,
    trophy3: u32,
    rating: u32,
    music_id: u32,
    difficulty: u32,
    team: String,
    // where is class?
    avatar_wear: u32,
    avatar_head: u32,
    avatar_face: u32,
    avatar_skin: u32,
    avatar_item: u32,
    avatar_front: u32,
    avatar_back: u32,
    music_id2: u32,
    group: Group,
    time: DateTime<Local>,
    players: u32,
    event_mode: bool,
    friend_only: bool,
}

impl Parse for Recruit {
    fn parse<R: Read>(reader: &mut R) -> io::Result<Self> {
        reader.read_exact(&mut [0u8; 15])?; // struct padding
        let flag = reader.read_u8()? != 0; // I guess?
        let unknown0 = reader.read_u32::<LE>()?; // still unknown...
        let host = Ipv4Addr::parse(reader)?;
        let aime_id = reader.read_u32::<LE>()?;
        reader.read_u32::<LE>()?; // always 0
        let name = String::parse(reader)?;
        let chara = reader.read_u32::<LE>()?;
        let chara_level = reader.read_u32::<LE>()?;
        let skill = reader.read_u32::<LE>()?;
        let skill_level = reader.read_u32::<LE>()?;
        let trophy = reader.read_u32::<LE>()?;
        let trophy2 = reader.read_u32::<LE>()?;
        let trophy3 = reader.read_u32::<LE>()?;
        let rating = reader.read_u32::<LE>()?;
        let music_id = reader.read_u32::<LE>()?;
        let difficulty = reader.read_u32::<LE>()?;
        reader.read_u64::<LE>()?; // always 1
        let team = String::parse(reader)?;
        reader.read_exact(&mut [0u8; 30])?; // wtf
        let avatar_wear = reader.read_u32::<LE>()?;
        let avatar_head = reader.read_u32::<LE>()?;
        let avatar_face = reader.read_u32::<LE>()?;
        let avatar_skin = reader.read_u32::<LE>()?;
        let avatar_item = reader.read_u32::<LE>()?;
        let avatar_front = reader.read_u32::<LE>()?;
        let avatar_back = reader.read_u32::<LE>()?;
        reader.read_exact(&mut [0u8; 16])?; // always 0
        let music_id2 = reader.read_u32::<LE>()?;
        let group = reader.read_u32::<LE>()?.into();
        reader.read_u32::<LE>()?; // event mode flag
        reader.read_u32::<LE>()?; // unknown
        reader.read_i32::<LE>()?; // always -1
        reader.read_exact(&mut [0u8; 5])?; // struct padding
        let time = DateTime::from_timestamp(reader.read_i32::<LE>()? as i64, 0)
            .unwrap_or_default()
            .with_timezone(&Local);
        let players = reader.read_u32::<LE>()?;
        let event_mode = reader.read_u8()? != 0;
        let friend_only = reader.read_u8()? != 0;

        Ok(Self {
            flag,
            unknown0,
            host,
            aime_id,
            name,
            chara,
            chara_level,
            skill,
            skill_level,
            trophy,
            trophy2,
            trophy3,
            rating,
            music_id,
            difficulty,
            team,
            avatar_wear,
            avatar_head,
            avatar_face,
            avatar_skin,
            avatar_item,
            avatar_front,
            avatar_back,
            music_id2,
            group,
            time,
            players,
            event_mode,
            friend_only,
        })
    }
}

pub fn dump(pkt: &[u8], out: &mut impl Write) -> anyhow::Result<()> {
    let _span = info_span!("dump", magic = hex_string(&pkt[0..4])).entered();

    let aes = Aes128Dec::new(b"CHUNICHUNICHUNIC".into());
    let mut buf = pkt[4..].to_vec();
    let (blocks, _) = InOutBuf::from(&mut buf[..]).into_chunks();
    aes.decrypt_blocks_inout(blocks);

    out.write_all(&buf)?;
    let mut r = Cursor::new(buf);

    let header = Header::parse(&mut r)?;
    let _span = info_span!("decrypt", ?header).entered();

    let archive_header = ArchiveHeader::parse(&mut r).unwrap();
    let _span = info_span!("archive", ?archive_header).entered();

    match header.command {
        Command::Recruit | Command::RecruitEnd => {
            let recruit = Recruit::parse(&mut r)?;
            info!("{:?}", recruit);
        }
        Command::Unknown(x) => {
            info!("Unknown command: {}", x);
        }
    }
    Ok(())
}
