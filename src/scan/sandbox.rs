//! Confining ffmpeg: a large C parser, handed anyone's bytes. Its process
//! gets no new privileges, no network (a network namespace of its own, and
//! Landlock's TCP rules), no file but the one blob it reads and the system's
//! libraries (Landlock), no write to any file, no core dump, no descriptor
//! of this server's but its pipes, and a bound on its memory. Code run by a
//! crafted file sees the blob and the libraries, and has its output pipe,
//! which is only ever read as pixels.
//!
//! Each part is applied where the kernel has it, and passed over where it
//! doesn't (Landlock before Linux 5.13, or user namespaces turned off),
//! unless confinement is required (`require`): then ffmpeg doesn't run
//! without files and network both shut off. `probe` says which it gets.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// The most memory ffmpeg maps: frames are at most `MAX_PIXELS`.
const MAX_MEMORY: u64 = 4 << 30;

/// Where an executable and its libraries may be: read, never written.
const SYSTEM: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/nix/store",
    "/gnu/store",
    "/dev/urandom",
];

/// Whether ffmpeg runs only fully confined.
static REQUIRED: AtomicBool = AtomicBool::new(false);

/// Run ffmpeg only if its files and network are both shut off.
pub fn require(required: bool) {
    REQUIRED.store(required, Ordering::Relaxed);
}

/// What confinement ffmpeg gets here.
pub struct Probe {
    /// Landlock's ABI; 0 for none.
    pub landlock: i64,
    /// Whether it gets a network namespace of its own.
    pub netns: bool,
}

impl Probe {
    /// Files shut off but the blob and the libraries.
    pub fn files(&self) -> bool {
        self.landlock >= 1
    }

    /// No network: a namespace of its own, or Landlock's TCP rules.
    pub fn network(&self) -> bool {
        self.netns || self.landlock >= 4
    }
}

/// What confinement `program` gets, by running it once (`-version`).
pub fn probe(program: &Path) -> Probe {
    let mut cmd = Command::new(program);
    cmd.arg("-version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: one system call between fork and exec.
    unsafe {
        cmd.pre_exec(|| check(libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET)));
    }
    Probe {
        landlock: landlock_abi(),
        netns: cmd.status().is_ok_and(|s| s.success()),
    }
}

fn landlock_abi() -> i64 {
    // SAFETY: asks the kernel its Landlock ABI, and nothing else.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    abi.max(0)
}

/// Confine `cmd` to reading `input`, if it's a file, and the system's
/// libraries.
pub fn confine(cmd: &mut Command, input: Option<&Path>) {
    let mut readable: Vec<CString> = SYSTEM.iter().map(|p| cstring(Path::new(p))).collect();
    // An ffmpeg of its own, as in /opt/ffmpeg/bin, reads its libraries
    // from beside it.
    if let Some(bin) = resolve(Path::new(cmd.get_program()))
        && let Some(home) = bin.parent().and_then(Path::parent)
        && home != Path::new("/")
    {
        readable.push(cstring(home));
    }
    let input = input.map(cstring);
    let required = REQUIRED.load(Ordering::Relaxed);
    // SAFETY: what runs between fork and exec makes only system calls,
    // with what was allocated above.
    unsafe {
        cmd.pre_exec(move || {
            restrict(&readable, input.as_ref(), required)?;
            Ok(())
        });
    }
}

fn cstring(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).unwrap_or_default()
}

/// The program `cmd` names, as `exec` finds it on the PATH.
fn resolve(program: &Path) -> Option<PathBuf> {
    if program.components().count() > 1 {
        return program.canonicalize().ok();
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(program))
        .find(|p| p.is_file())
        .and_then(|p| p.canonicalize().ok())
}

/// In the child, before exec: async-signal-safe calls only.
fn restrict(readable: &[CString], input: Option<&CString>, required: bool) -> io::Result<()> {
    // SAFETY: plain system calls on this process alone.
    unsafe {
        // Every descriptor but stdio is closed at exec: LMDB's, the
        // listeners', other uploads' temp files.
        if libc::close_range(
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
        ) != 0
        {
            for fd in 3..4096 {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
        for (resource, max) in [
            (libc::RLIMIT_AS, MAX_MEMORY),
            (libc::RLIMIT_FSIZE, 0),
            (libc::RLIMIT_CORE, 0),
        ] {
            let lim = libc::rlimit {
                rlim_cur: max,
                rlim_max: max,
            };
            check(libc::setrlimit(resource, &lim))?;
        }
        // No network at all, where unprivileged user namespaces are allowed.
        let netns = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) == 0;
        let abi = landlock(readable, input)?;
        if required && (abi < 1 || !(netns || abi >= 4)) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}

fn check(r: libc::c_int) -> io::Result<()> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// Landlock's ABI, from linux/landlock.h.
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;
const FS_EXECUTE: u64 = 1 << 0;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Every file access is refused but reading `readable` and `input`, and
/// (ABI 4 on) every TCP bind and connect, and (ABI 6 on) signals and
/// abstract sockets beyond the process. The ABI applied; 0 for none.
fn landlock(readable: &[CString], input: Option<&CString>) -> io::Result<i64> {
    // SAFETY: Landlock's system calls, given structs laid out as its header
    // has them and descriptors this function opened.
    unsafe {
        let abi = libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        );
        if abi < 1 {
            // Not in this kernel, or turned off.
            return Ok(0);
        }
        // Each ABI adds rights: all of those it knows are handled.
        let fs_bits = match abi {
            1 => 13,
            2 => 14,
            3 | 4 => 15,
            _ => 16,
        };
        let attr = RulesetAttr {
            handled_access_fs: (1u64 << fs_bits) - 1,
            handled_access_net: if abi >= 4 { 0b11 } else { 0 },
            scoped: if abi >= 6 { 0b11 } else { 0 },
        };
        let size = match abi {
            1..=3 => 8,
            4 | 5 => 16,
            _ => 24,
        };
        let ruleset = libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            size as usize,
            0u32,
        ) as libc::c_int;
        check(ruleset)?;
        let allow = |path: &CString, access: u64| -> io::Result<()> {
            let fd = libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
            if fd < 0 {
                // Not on this system.
                return Ok(());
            }
            let mut st: libc::stat = std::mem::zeroed();
            let dir = libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFDIR;
            let rule = PathBeneathAttr {
                // A file takes no directory's rights.
                allowed_access: if dir { access } else { access & !FS_READ_DIR },
                parent_fd: fd,
            };
            let r = libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            );
            libc::close(fd);
            check(r as libc::c_int)
        };
        for path in readable {
            allow(path, FS_READ_FILE | FS_READ_DIR | FS_EXECUTE)?;
        }
        if let Some(path) = input {
            allow(path, FS_READ_FILE)?;
        }
        let r = libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32);
        libc::close(ruleset);
        check(r as libc::c_int)?;
        Ok(abi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn landlocked() -> bool {
        landlock_abi() >= 4
    }

    fn ok(mut cmd: Command) -> bool {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn reads_only_its_input_and_reaches_nothing() {
        if !landlocked() {
            eprintln!("no Landlock with network rules here: untested");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (input, other) = (dir.path().join("blob"), dir.path().join("secret"));
        std::fs::write(&input, b"blob").unwrap();
        std::fs::write(&other, b"secret").unwrap();
        let cat = |path: &Path, confined: bool| {
            let mut cmd = Command::new("cat");
            cmd.arg(path);
            if confined {
                confine(&mut cmd, Some(&input));
            }
            ok(cmd)
        };
        assert!(cat(&input, true));
        assert!(cat(&other, false), "control");
        assert!(!cat(&other, true));

        let write = |confined: bool| {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg(format!("echo x > {}", dir.path().join("new").display()));
            if confined {
                confine(&mut cmd, None);
            }
            ok(cmd)
        };
        assert!(!write(true));
        assert!(write(false), "control");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connect = |confined: bool| {
            let mut cmd = Command::new("bash");
            cmd.arg("-c")
                .arg(format!("exec 3<>/dev/tcp/127.0.0.1/{port}"));
            if confined {
                confine(&mut cmd, None);
            }
            ok(cmd)
        };
        assert!(!connect(true));
        assert!(connect(false), "control");
    }

    #[test]
    fn probe_says_what_ffmpeg_gets() {
        let p = probe(Path::new("true"));
        assert_eq!(p.landlock, landlock_abi());
        // Requiring it is global: only tried where it holds, so other
        // tests' ffmpeg runs meanwhile aren't refused.
        if !(p.files() && p.network()) {
            eprintln!("not fully confined here: untested");
            return;
        }
        require(true);
        let mut cmd = Command::new("true");
        confine(&mut cmd, None);
        let ran = ok(cmd);
        require(false);
        assert!(ran);
    }
}
