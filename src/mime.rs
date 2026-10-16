//! Content types: cleaning up what clients declare, guessing from the bytes
//! when they don't, the extension a type's URLs get, and which types are
//! worth compressing.

/// The longest type kept; anything longer is someone's mistake.
const MAX_LEN: usize = 127;

/// A declared Content-Type reduced to `type/subtype`, lowercase, or `None` if
/// it isn't one (or says nothing more than octet-stream).
pub fn normalize(declared: &str) -> Option<String> {
    let essence = declared.split(';').next()?.trim().to_ascii_lowercase();
    let (ty, sub) = essence.split_once('/')?;
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    if essence.len() > MAX_LEN || !token(ty) || !token(sub) || essence == "application/octet-stream"
    {
        return None;
    }
    Some(essence)
}

/// A type for bytes that came without one, from their first few KiB.
pub fn sniff(head: &[u8]) -> Option<String> {
    infer::get(head).map(|t| t.mime_type().to_string())
}

/// The extension a blob's URL gets, BUD-02 asking for one. Unknown types,
/// and blobs with none, get `bin`.
pub fn extension(ty: Option<&str>) -> &'static str {
    let Some(ty) = ty else { return "bin" };
    match ty {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/avif" => "avif",
        "image/heic" => "heic",
        "image/svg+xml" => "svg",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        "image/bmp" => "bmp",
        "image/tiff" => "tiff",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "video/quicktime" => "mov",
        "video/x-matroska" => "mkv",
        "video/mpeg" => "mpeg",
        "audio/mpeg" => "mp3",
        "audio/mp4" | "audio/x-m4a" => "m4a",
        "audio/ogg" => "ogg",
        "audio/wav" | "audio/x-wav" => "wav",
        "audio/flac" => "flac",
        "audio/webm" => "weba",
        "audio/aac" => "aac",
        "text/plain" => "txt",
        "text/html" => "html",
        "text/css" => "css",
        "text/javascript" | "application/javascript" => "js",
        "text/markdown" => "md",
        "text/csv" => "csv",
        "text/xml" | "application/xml" => "xml",
        "application/json" => "json",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/gzip" => "gz",
        "application/x-tar" => "tar",
        "application/wasm" => "wasm",
        "application/vnd.android.package-archive" => "apk",
        "font/woff" => "woff",
        "font/woff2" => "woff2",
        "font/ttf" => "ttf",
        "font/otf" => "otf",
        _ => "bin",
    }
}

/// Whether a type is worth a brotli copy, or gzip on the way out: text and
/// its kin. Media and archives are compressed already.
pub fn compressible(ty: Option<&str>) -> bool {
    let Some(ty) = ty else { return false };
    ty.starts_with("text/")
        || ty.ends_with("+json")
        || ty.ends_with("+xml")
        || matches!(
            ty,
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/wasm"
                | "application/x-ndjson"
                | "font/ttf"
                | "font/otf"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_declared_types() {
        assert_eq!(
            normalize("Text/HTML; charset=utf-8").as_deref(),
            Some("text/html")
        );
        assert_eq!(normalize("image/png").as_deref(), Some("image/png"));
        assert_eq!(normalize("application/octet-stream"), None);
        assert_eq!(normalize("nonsense"), None);
        assert_eq!(normalize("a/b c"), None);
        assert_eq!(normalize(""), None);
    }

    #[test]
    fn sniffs_and_names() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        assert_eq!(sniff(png).as_deref(), Some("image/png"));
        assert_eq!(extension(Some("image/png")), "png");
        assert_eq!(extension(Some("x/unknown")), "bin");
        assert_eq!(extension(None), "bin");
        assert!(compressible(Some("text/javascript")));
        assert!(compressible(Some("application/ld+json")));
        assert!(!compressible(Some("image/jpeg")));
        assert!(!compressible(None));
    }
}
