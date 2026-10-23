//! Asks the user things through a pinentry program (Assuan protocol), the
//! same mechanism gpg-agent uses: `pinentry-gnome3`, `pinentry-qt`, ... all
//! work, and tests plug in a scripted one.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

/// Answer to an access confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    Once,
    Always,
    Deny,
}

#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    #[error("could not run the prompter {0:?}: {1}")]
    Spawn(String, std::io::Error),
    #[error("prompter protocol error: {0}")]
    Protocol(String),
    #[error("the prompt timed out")]
    Timeout,
}

// libgpg-error codes as pinentry reports them (source 5 = pinentry).
const ERR_CANCELED: &str = "83886179";
const ERR_NOT_CONFIRMED: &str = "83886194";

#[derive(Clone)]
pub struct Prompter {
    program: String,
    timeout: Duration,
}

struct Conversation {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

fn escape(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn unescape(s: &str) -> Zeroizing<String> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

enum Reply {
    Ok(Option<Zeroizing<String>>),
    Err(String),
}

impl Conversation {
    async fn start(program: &str) -> Result<Self, PromptError> {
        let mut child = Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| PromptError::Spawn(program.to_owned(), e))?;
        let stdin = child.stdin.take().ok_or_else(|| PromptError::Protocol("no stdin".into()))?;
        let stdout = BufReader::new(child.stdout.take().ok_or_else(|| PromptError::Protocol("no stdout".into()))?);
        let mut c = Conversation { child, stdin, stdout };
        match c.read_reply().await? {
            Reply::Ok(_) => Ok(c),
            Reply::Err(e) => Err(PromptError::Protocol(format!("greeting: {e}"))),
        }
    }

    async fn read_reply(&mut self) -> Result<Reply, PromptError> {
        let mut data: Option<Zeroizing<String>> = None;
        loop {
            let mut line = Zeroizing::new(String::new());
            let n = self.stdout.read_line(&mut line).await.map_err(|e| PromptError::Protocol(e.to_string()))?;
            if n == 0 {
                return Err(PromptError::Protocol("prompter exited".into()));
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line == "OK" || line.starts_with("OK ") {
                return Ok(Reply::Ok(data));
            }
            if let Some(rest) = line.strip_prefix("ERR ") {
                return Ok(Reply::Err(rest.to_owned()));
            }
            if let Some(d) = line.strip_prefix("D ") {
                let chunk = unescape(d);
                data = Some(match data.take() {
                    Some(prev) => Zeroizing::new(format!("{}{}", prev.as_str(), chunk.as_str())),
                    None => chunk,
                });
            }
            // "S" status and "#" comment lines are ignored.
        }
    }

    async fn command(&mut self, cmd: &str) -> Result<Reply, PromptError> {
        self.stdin.write_all(cmd.as_bytes()).await.map_err(|e| PromptError::Protocol(e.to_string()))?;
        self.stdin.write_all(b"\n").await.map_err(|e| PromptError::Protocol(e.to_string()))?;
        self.stdin.flush().await.map_err(|e| PromptError::Protocol(e.to_string()))?;
        self.read_reply().await
    }

    async fn set(&mut self, cmd: &str, value: &str) -> Result<(), PromptError> {
        match self.command(&format!("{cmd} {}", escape(value))).await? {
            Reply::Ok(_) => Ok(()),
            Reply::Err(e) => Err(PromptError::Protocol(format!("{cmd}: {e}"))),
        }
    }

    async fn finish(mut self) {
        let _ = self.command("BYE").await;
        let _ = self.child.wait().await;
    }
}

impl Prompter {
    pub fn new(program: impl Into<String>, timeout: Duration) -> Self {
        Prompter { program: program.into(), timeout }
    }

    /// Asks for a password; `None` when the user cancelled.
    pub async fn password(
        &self,
        description: &str,
        error: Option<&str>,
    ) -> Result<Option<Zeroizing<String>>, PromptError> {
        tokio::time::timeout(self.timeout, async {
            let mut c = Conversation::start(&self.program).await?;
            c.set("SETTITLE", "Unlock keyring").await?;
            c.set("SETDESC", description).await?;
            c.set("SETPROMPT", "Master password:").await?;
            if let Some(e) = error {
                c.set("SETERROR", e).await?;
            }
            let reply = c.command("GETPIN").await?;
            c.finish().await;
            match reply {
                Reply::Ok(pin) => Ok(Some(pin.unwrap_or_default())),
                Reply::Err(e) if e.starts_with(ERR_CANCELED) => Ok(None),
                Reply::Err(e) => Err(PromptError::Protocol(format!("GETPIN: {e}"))),
            }
        })
        .await
        .map_err(|_| PromptError::Timeout)?
    }

    /// Asks whether an application may use an item.
    pub async fn confirm(&self, description: &str) -> Result<Confirm, PromptError> {
        tokio::time::timeout(self.timeout, async {
            let mut c = Conversation::start(&self.program).await?;
            c.set("SETTITLE", "Keyring access").await?;
            c.set("SETDESC", description).await?;
            c.set("SETOK", "Allow once").await?;
            c.set("SETNOTOK", "Always allow").await?;
            c.set("SETCANCEL", "Deny").await?;
            let reply = c.command("CONFIRM").await?;
            c.finish().await;
            Ok(match reply {
                Reply::Ok(_) => Confirm::Once,
                Reply::Err(e) if e.starts_with(ERR_NOT_CONFIRMED) => Confirm::Always,
                Reply::Err(_) => Confirm::Deny,
            })
        })
        .await
        .map_err(|_| PromptError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_round_trips() {
        let s = "50% off\nline two\r";
        assert_eq!(escape(s), "50%25 off%0Aline two%0D");
        assert_eq!(&*unescape(&escape(s)), s);
        assert_eq!(&*unescape("pa%25ss%"), "pa%ss%");
        assert_eq!(&*unescape("%zz"), "%zz");
    }
}
