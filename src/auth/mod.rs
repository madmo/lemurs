mod pam;
pub mod utmpx;

use ::pam::{Authenticator, PasswordConv};
use log::{error, info};
use nix::{sys::wait::waitpid, unistd::fork};

pub use crate::auth::pam::AuthenticationError;
use crate::{auth::pam::open_session, StartSessionError};

pub struct AuthUserInfo<'a> {
    // This is used to keep the user session. If the struct is dropped then the user session is
    // also automatically dropped.
    #[allow(dead_code)]
    authenticator: Authenticator<'a, PasswordConv>,

    #[allow(dead_code)]
    pub username: String,

    pub uid: libc::uid_t,
    pub primary_gid: libc::gid_t,
    pub all_gids: Vec<libc::gid_t>,
    pub home_dir: String,
    pub shell: String,
}

pub fn try_auth<'a, F>(
    username: &str,
    password: &str,
    pam_service: &str,
    mut session_func: F,
) -> Result<(), StartSessionError>
where
    F: FnMut(AuthUserInfo<'a>) -> Result<(), StartSessionError>,
{
    info!("Login attempt for '{username}'");

    let fork_result = unsafe { fork() };

    match fork_result {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            let _ = waitpid(child, None).unwrap();
            Ok(())
        }
        Ok(nix::unistd::ForkResult::Child) => {
            let session = open_session(username, password, pam_service).inspect_err(|err| {
                info!(
                    "Authentication failed for '{}'. Reason: {}",
                    username,
                    err.to_string()
                );
            })?;

            session_func(session)?;

            Ok(())
        }
        Err(e) => {
            error!("fork failed: {e}");
            Err(StartSessionError::ForkFailed(e))
        }
    }
}
