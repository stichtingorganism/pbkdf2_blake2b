// Copyright 2018 Stichting Organism
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//pbkdf errors

use std::{fmt, error};

pub enum Error {
    //Invalid format is passed to function
    InvalidFormat,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidFormat => "invalid format is passed to PBKDF2"
        })
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::InvalidFormat => "invalid format is passed to PBKDF2",
        }
    }
}