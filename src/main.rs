// ecc: Elliptic curve cryptography command-line utility
//
// Written in 2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

#[macro_use]
extern crate clap;
#[macro_use]
extern crate amplify;

mod edwards;
mod koblitz;

use clap::{AppSettings, Clap};

use crate::koblitz::SecpCommand;

#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From,
    Error
)]
#[display(inner)]
pub enum Error {
    #[from]
    Secp(secp256k1::Error),
}

#[derive(Clap, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[clap(
    name = "ecc",
    bin_name = "ecc",
    author,
    version,
    about = "Elliptic curve cryptography command-line utility",
    setting = AppSettings::ColoredHelp,
)]
pub struct Opts {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

pub trait Exec {
    fn exec(&self) -> Result<String, Error>;
}

#[derive(Clap, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[clap(setting = AppSettings::ColoredHelp)]
pub enum Command {
    /// Operations with Secp256k1 curve
    Secp {
        #[clap(subcommand)]
        subcommand: SecpCommand,
    },
}

impl Exec for Command {
    fn exec(&self) -> Result<String, Error> {
        match self {
            Command::Secp { subcommand } => subcommand.exec(),
        }
    }
}

fn main() -> Result<(), Error> {
    let opts = Opts::parse();
    let res = opts.command.exec()?;
    println!("{}", res);
    Ok(())
}
