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

use clap::AppSettings;
use secp256k1::rand::thread_rng;
use secp256k1::schnorrsig::KeyPair;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use super::{Error, Exec};

#[derive(Clap, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[clap(setting = AppSettings::ColoredHelp)]
pub enum SecpCommand {
    /// Generates new number from the field F_p, printing it to the standard
    /// output
    New {
        /// Generate number that will match even EC point value
        #[clap(short, long)]
        even: bool,
    },

    /// Generates new number from the field F_p and the matching elliptic curve
    /// point, printing both to the standard output
    NewPair {
        /// Generate number that will match even EC point value
        #[clap(short, long)]
        even: bool,
    },

    /// Scalar multiplication on generator point `G`
    Mul { scalar: secp256k1::SecretKey },

    /// Addition of two elliptic curve points
    Exp { point1: secp256k1::PublicKey, point2: secp256k1::PublicKey },

    /// Addition of an elliptic curve point and scalar multiplied on generator
    AddExp { point: secp256k1::PublicKey, scalar: secp256k1::SecretKey },

    /// Addition of two numbers from F_p field
    Add { scalar1: secp256k1::SecretKey, scalart2: secp256k1::SecretKey },
}

impl Exec for SecpCommand {
    fn exec(&self) -> Result<String, Error> {
        let secp = Secp256k1::new();
        Ok(match self {
            SecpCommand::New { even: false } => {
                SecretKey::new(&mut thread_rng()).to_string()
            }
            SecpCommand::New { even: true } => {
                let _ = KeyPair::new(&secp, &mut thread_rng());
                unimplemented!(
                    "Generation of even-only keys is not yet fully \
                     implemented in Secp256k1 library"
                );
            }
            SecpCommand::NewPair { even: false } => {
                let sk = SecretKey::new(&mut thread_rng());
                let pk = PublicKey::from_secret_key(&secp, &sk);
                format!("{}\n{}", sk, pk)
            }
            SecpCommand::NewPair { even: true } => {
                let _ = KeyPair::new(&secp, &mut thread_rng());
                unimplemented!(
                    "Generation of even-only keys is not yet fully \
                     implemented in Secp256k1 library"
                );
            }
            SecpCommand::Mul { scalar } => {
                PublicKey::from_secret_key(&secp, scalar).to_string()
            }
            SecpCommand::Exp { point1, point2 } => {
                point1.combine(&point2)?.to_string()
            }
            SecpCommand::AddExp { mut point, scalar } => {
                point.add_exp_assign(&secp, &scalar[..])?;
                point.to_string()
            }
            SecpCommand::Add { mut scalar1, scalart2: scalar2 } => {
                scalar1.add_assign(&scalar2[..])?;
                scalar1.to_string()
            }
        })
    }
}
