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
    #[error("refusing to run the prompter: {0}")]
    Untrusted(String),
    #[error("prompter protocol error: {0}")]
    Protocol(String),
    #[error("the prompt timed out")]
    Timeout,
}

// libgpg-error codes as pinentry reports them (source 5 = pinentry).
const ERR_CANCELED: &str = "83886179";
const ERR_NOT_CONFIRMED: &str = "83886194";

/// The error code of an `ERR` reply: its first word, compared whole.
fn err_code(err: &str) -> &str {
    err.split_whitespace().next().unwrap_or_default()
}

/// Whether an `ERR` reply is the user's own "no": cancel or not confirmed.
fn is_users_no(err: &str) -> bool {
    matches!(err_code(err), ERR_CANCELED | ERR_NOT_CONFIRMED)
}

/// Checks the program again right before it runs (ADR 0008: a pinentry
/// that became writable since the daemon started is refused).
pub type Guard = std::sync::Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
pub struct Prompter {
    program: String,
    timeout: Duration,
    guard: Option<Guard>,
}

struct Conversation {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// Characters that are not controls but still change what text looks like:
/// the line and paragraph separators (U+2028, U+2029) and every character of
/// general category Cf (Unicode 15.1), which std cannot query: soft hyphen,
/// Arabic and Syriac marks, ZWSP/ZWNJ/ZWJ, LRM/RLM/ALM, the bidi embeddings,
/// overrides and isolates, invisible operators, BOM, interlinear
/// annotation, a few script-specific format marks, and the tag characters.
const INVISIBLE: &[(char, char)] = &[
    ('\u{ad}', '\u{ad}'),
    ('\u{600}', '\u{605}'),
    ('\u{61c}', '\u{61c}'),
    ('\u{6dd}', '\u{6dd}'),
    ('\u{70f}', '\u{70f}'),
    ('\u{890}', '\u{891}'),
    ('\u{8e2}', '\u{8e2}'),
    ('\u{180e}', '\u{180e}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{2028}', '\u{202e}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{110bd}', '\u{110bd}'),
    ('\u{110cd}', '\u{110cd}'),
    ('\u{13430}', '\u{1343f}'),
    ('\u{1bca0}', '\u{1bca3}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0001}', '\u{e0001}'),
    ('\u{e0020}', '\u{e007f}'),
];

/// Whether `c` is in [`INVISIBLE`].
pub fn is_invisible(c: char) -> bool {
    INVISIBLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// `s` on one line for a prompt: line breaks, every other control character
/// and every invisible format character (bidi overrides included) become
/// U+FFFD, so a file name or a label cannot add or reorder text.
pub fn one_line(s: &str) -> String {
    s.chars().map(|c| if c.is_control() || is_invisible(c) { '\u{fffd}' } else { c }).collect()
}

fn escape(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn unescape(s: &str) -> Zeroizing<String> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c == b'%'
            && i + 2 < bytes.len()
            && let Some(b) = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(c);
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
        Prompter { program: program.into(), timeout, guard: None }
    }

    /// A prompter that runs `guard` on the program before every start.
    pub fn guarded(program: impl Into<String>, timeout: Duration, guard: Guard) -> Self {
        Prompter { guard: Some(guard), ..Self::new(program, timeout) }
    }

    async fn start(&self) -> Result<Conversation, PromptError> {
        if let Some(guard) = &self.guard {
            guard(&self.program).map_err(PromptError::Untrusted)?;
        }
        Conversation::start(&self.program).await
    }

    /// Asks for a password; `None` when the user cancelled.
    pub async fn password(
        &self,
        description: &str,
        error: Option<&str>,
    ) -> Result<Option<Zeroizing<String>>, PromptError> {
        tokio::time::timeout(self.timeout, async {
            let mut c = self.start().await?;
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
                Reply::Err(e) if err_code(&e) == ERR_CANCELED => Ok(None),
                Reply::Err(e) => Err(PromptError::Protocol(format!("GETPIN: {e}"))),
            }
        })
        .await
        .map_err(|_| PromptError::Timeout)?
    }

    /// Asks whether an application may use an item. Without `offer_always`
    /// there is no second question: the answer is `Once` or `Deny`.
    pub async fn confirm(&self, description: &str, offer_always: bool) -> Result<Confirm, PromptError> {
        tokio::time::timeout(self.timeout, async {
            let mut c = self.start().await?;
            c.set("SETTITLE", "Keyring access").await?;
            c.set("SETDESC", description).await?;
            c.set("SETOK", "Allow").await?;
            c.set("SETCANCEL", "Deny").await?;
            // Only an explicit OK grants anything. Cancel and "not confirmed"
            // are the user's no; any other error means the question was never
            // put (pinentry-curses without a terminal, ...) and is a failure.
            let allowed = match c.command("CONFIRM").await? {
                Reply::Ok(_) => true,
                Reply::Err(e) if is_users_no(&e) => false,
                Reply::Err(e) => {
                    c.finish().await;
                    return Err(PromptError::Protocol(format!("CONFIRM: {e}")));
                }
            };
            if !allowed || !offer_always {
                c.finish().await;
                return Ok(if allowed { Confirm::Once } else { Confirm::Deny });
            }
            c.set("SETDESC", "Remember this decision for this application?").await?;
            c.set("SETOK", "Always allow").await?;
            c.set("SETCANCEL", "Only this time").await?;
            let remember = matches!(c.command("CONFIRM").await?, Reply::Ok(_));
            c.finish().await;
            Ok(if remember { Confirm::Always } else { Confirm::Once })
        })
        .await
        .map_err(|_| PromptError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_guarded_prompter_checks_the_program_before_each_start() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let refuse: Guard = std::sync::Arc::new(move |p: &str| {
            log.lock().map_err(|e| e.to_string())?.push(p.to_owned());
            Err(format!("{p} became writable"))
        });
        let p = Prompter::guarded("/nonexistent/pinentry", Duration::from_secs(1), refuse);
        let e = p.password("x", None).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert_eq!(e, "refusing to run the prompter: /nonexistent/pinentry became writable");
        assert!(matches!(p.confirm("x", true).await, Err(PromptError::Untrusted(_))));
        assert_eq!(seen.lock().map(|s| s.len()).unwrap_or_default(), 2, "checked before every start");

        let allow: Guard = std::sync::Arc::new(|_: &str| Ok(()));
        let p = Prompter::guarded("/nonexistent/pinentry", Duration::from_secs(1), allow);
        assert!(matches!(p.password("x", None).await, Err(PromptError::Spawn(..))), "allowed, then started");
    }

    #[test]
    fn one_line_replaces_line_breaks_and_controls() {
        assert_eq!(one_line("/usr/bin/git"), "/usr/bin/git");
        assert_eq!(
            one_line("a\nb\rc\td\u{1b}e\u{7f}f\u{9b}g\u{2028}h\u{2029}i"),
            "a\u{fffd}b\u{fffd}c\u{fffd}d\u{fffd}e\u{fffd}f\u{fffd}g\u{fffd}h\u{fffd}i"
        );
        assert_eq!(one_line("naïve ✓"), "naïve ✓");
    }

    /// Every character the review named, plus the rest of category Cf.
    const INVISIBLE: &[char] = &[
        '\u{ad}',
        '\u{61c}',
        '\u{200b}',
        '\u{200c}',
        '\u{200d}',
        '\u{200e}',
        '\u{200f}',
        '\u{202a}',
        '\u{202b}',
        '\u{202c}',
        '\u{202d}',
        '\u{202e}',
        '\u{2060}',
        '\u{2061}',
        '\u{2062}',
        '\u{2063}',
        '\u{2064}',
        '\u{2066}',
        '\u{2067}',
        '\u{2068}',
        '\u{2069}',
        '\u{feff}',
        '\u{2028}',
        '\u{2029}',
        '\u{600}',
        '\u{6dd}',
        '\u{180e}',
        '\u{206f}',
        '\u{fffb}',
        '\u{110bd}',
        '\u{e0001}',
        '\u{e007f}',
    ];

    #[test]
    fn one_line_replaces_bidi_and_other_invisible_format_characters() {
        for &c in INVISIBLE {
            assert_eq!(one_line(&format!("a{c}b")), "a\u{fffd}b", "U+{:04X}", u32::from(c));
            assert!(is_invisible(c), "U+{:04X}", u32::from(c));
        }
        for c in ['a', ' ', 'é', '\u{2010}', '\u{2070}', '\u{fffd}', '\u{e0080}'] {
            assert!(!is_invisible(c), "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn escaping_round_trips() {
        let s = "50% off\nline two\r";
        assert_eq!(escape(s), "50%25 off%0Aline two%0D");
        assert_eq!(&*unescape(&escape(s)), s);
        assert_eq!(&*unescape("pa%25ss%"), "pa%ss%");
        assert_eq!(&*unescape("%zz"), "%zz");
    }

    #[test]
    fn only_cancel_and_not_confirmed_are_a_users_no() {
        assert!(is_users_no("83886179 Operation cancelled"));
        assert!(is_users_no("83886194 Not confirmed"));
        assert!(!is_users_no("83918950 Inappropriate ioctl for device"));
        assert!(!is_users_no("garbage"));
        assert!(!is_users_no("838861790 longer code"), "the whole code, not a prefix");
        assert!(!is_users_no("838861940"));
        assert!(is_users_no("83886179"));
    }
}
