// Copyright (c) 2019 - 2020 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use super::logger;
use nix::{mount, sched};
use sched::{unshare, CloneFlags};
use std::env;

pub fn init() {
    color_eyre::install().unwrap();
    logger::init();
    log::set_max_level(log::LevelFilter::Debug);

    // TODO make the test independent of the workspace structure
    // set the CWD to the root
    env::set_current_dir("..").unwrap();

    // Enter a mount namespace. This needs to be done before spawning
    // the tokio threadpool.
    unshare(CloneFlags::CLONE_NEWNS).unwrap();

    // Enable backtrace dumping
    env::set_var("RUST_BACKTRACE", "1");

    // Set the mount propagation to private on root. This ensures that *all*
    // mounts get cleaned up upon process termination. The approach to bind
    // mount the run_dir only (this is where the mounts from northstar happen)
    // doesn't work for the tests since the run_dir is a tempdir which is a
    // random dir on every run. Checking at the beginning of the tests if
    // run_dir is bind mounted - a leftover from a previous crash - obviously
    // doesn't work. Technically, it is only necessary set the propagation of
    // the parent mount of the run_dir, but this not easy to find and the change
    // of mount propagation on root is fine for the tests which are developemnt
    // only.
    mount::mount(
        Some("/"),
        "/",
        Option::<&str>::None,
        mount::MsFlags::MS_PRIVATE | mount::MsFlags::MS_REC,
        Option::<&'static [u8]>::None,
    )
    .expect(
        "Failed to set mount propagation to private on
    root",
    );
}
#[macro_export]
macro_rules! test {
    ($name:ident, $e:expr) => {
        rusty_fork::rusty_fork_test! {
            #![rusty_fork(timeout_ms = 300000)]
            #[test]
            fn $name() {
                northstar_tests::macros::init();
                match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name(stringify!($name))
                    .build()
                    .expect("Failed to start runtime")
                    .block_on(async { $e }) {
                        Ok(_) => std::process::exit(0),
                        Err(e) => panic!("{}", e),
                    }
            }
        }
    };
}
