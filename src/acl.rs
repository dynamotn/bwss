//! Identifies the application behind a D-Bus call.
//!
//! The executable path is what the item ACL records. It is a speed bump, not
//! a sandbox: every process of the same user can still ptrace the daemon or
//! the client. It does stop one ordinary app from quietly reading another
//! app's secrets, which plain Secret Service implementations allow.

use zbus::{Connection, fdo::DBusProxy, message::Header, names::BusName};

pub const UNKNOWN: &str = "(unknown application)";

pub async fn caller_executable(conn: &Connection, header: &Header<'_>) -> String {
    let Some(sender) = header.sender() else { return UNKNOWN.into() };
    let Ok(proxy) = DBusProxy::new(conn).await else { return UNKNOWN.into() };
    let Ok(pid) = proxy.get_connection_unix_process_id(BusName::Unique(sender.to_owned())).await else {
        return UNKNOWN.into();
    };
    executable_of(pid).unwrap_or_else(|| UNKNOWN.into())
}

fn executable_of(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let s = path.to_string_lossy();
    Some(s.strip_suffix(" (deleted)").unwrap_or(&s).to_owned())
}
