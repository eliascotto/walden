// Website categories from a read-only walden-list snapshot (manifest,
// checksums.txt, one domains file per category). Every file is verified
// against the manifest before any domain reaches a block; a mismatch is an
// error, not a shorter list.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::entry::valid_catalog_domain;
use crate::fetch;

pub const MANIFEST_FILE_NAME: &str = "manifest.json";
pub const CHECKSUMS_FILE_NAME: &str = "checksums.txt";
const CATEGORY_DIRECTORY: &str = "categories";

// The only distribution format this Walden version reads. A walden-list
// snapshot declaring anything else needs explicit handling here rather than a
// best guess at what changed.
const MANIFEST_FORMAT: &str = "walden-domain-registry-v1";
const MANIFEST_SCHEMA_VERSION: u32 = 1;
const CATEGORY_FORMAT: &str = "domains-v1";

pub const CATALOG_DIR_ENV: &str = "WALDEN_CATALOG_DIR";
pub const CATALOG_CACHE_DIR_ENV: &str = "WALDEN_CATALOG_CACHE_DIR";
pub const BUNDLED_CATALOG_DIR_ENV: &str = "WALDEN_BUNDLED_CATALOG_DIR";
#[cfg(target_os = "macos")]
pub const UPDATED_CATALOG_DIR: &str = "/usr/local/var/walden/catalog/v1";
#[cfg(not(target_os = "macos"))]
pub const UPDATED_CATALOG_DIR: &str = "/var/lib/walden/catalog/v1";

#[cfg(target_os = "macos")]
pub const BUNDLED_CATALOG_DIR: &str = "/usr/local/share/walden/catalog/v1";
#[cfg(not(target_os = "macos"))]
pub const BUNDLED_CATALOG_DIR: &str = "/usr/share/walden/catalog/v1";

pub const DEFAULT_SOURCE_URL: &str =
    "https://raw.githubusercontent.com/eliascotto/walden-list/main/dist/v1";

// Read-only install: category selection is config, not a file edit.
pub const DIRECTORY_MODE: u32 = 0o555;
pub const FILE_MODE: u32 = 0o444;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub description: String,
    pub warning: Option<String>,
    pub recommended: bool,
    pub confidence: Option<String>,
    pub variant: Option<String>,

    pub license: String,
    pub domains: usize,
    pub bytes: u64,
    pub sha256: String,

    relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub id: String,
    pub repository: Option<String>,
    pub commit: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug)]
pub struct Catalog {
    root: PathBuf,
    version: String,
    generated_at: String,
    manifest_sha256: String,
    categories: Vec<Category>,
    sources: Vec<Source>,

    domains: BTreeMap<String, OnceLock<Vec<String>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogCacheState {
    Absent,
    Incomplete { detail: String },
    Invalid { detail: String },
    Valid,
}

#[derive(Debug)]
pub struct CatalogSelection {
    catalog: Catalog,
    cache_state: Option<CatalogCacheState>,
}

impl CatalogSelection {
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn cache_state(&self) -> Option<&CatalogCacheState> {
        self.cache_state.as_ref()
    }

    pub fn fallback_notice(&self) -> Option<String> {
        let condition = match self.cache_state.as_ref()? {
            CatalogCacheState::Incomplete { .. } => "incomplete",
            CatalogCacheState::Invalid { .. } => "invalid",
            CatalogCacheState::Absent | CatalogCacheState::Valid => return None,
        };
        Some(format!(
            "Using bundled catalog; an {condition} downloaded update was ignored. Run `sudo walden catalog update` to repair it."
        ))
    }

    pub fn into_catalog(self) -> Catalog {
        self.catalog
    }
}

#[derive(Deserialize)]
struct RawManifest {
    format: String,
    schema_version: u32,
    generated_at: String,
    categories: BTreeMap<String, RawCategory>,
    #[serde(default)]
    sources: BTreeMap<String, RawSource>,
}

// Not `deny_unknown_fields`: walden-list may add category metadata within the
// same schema version without breaking Walden.
#[derive(Deserialize)]
struct RawCategory {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    recommended: bool,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    variant: Option<String>,
    license: String,
    format: String,
    path: String,
    sha256: String,
    bytes: u64,
    domains: usize,
}

#[derive(Deserialize)]
struct RawSource {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    license: Option<String>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' => index != 0 && index + 1 != id.len(),
            _ => false,
        })
        && !id.contains("--")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// Canonical path keeps manifest entries inside the catalog directory.
fn category_relative_path(id: &str) -> String {
    format!("{CATEGORY_DIRECTORY}/{id}.txt")
}

fn category_id_of(relative_path: &str) -> anyhow::Result<&str> {
    let file = relative_path
        .strip_prefix(&format!("{CATEGORY_DIRECTORY}/"))
        .and_then(|file| file.strip_suffix(".txt"))
        .with_context(|| {
            format!("{relative_path:?} is not a {CATEGORY_DIRECTORY}/<id>.txt category file")
        })?;

    ensure!(
        valid_id(file),
        "{relative_path:?} names an invalid category"
    );
    Ok(file)
}

fn parse_checksums(contents: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut recorded = BTreeMap::new();

    for (index, line) in contents.lines().enumerate() {
        let number = index + 1;
        if line.trim().is_empty() {
            continue;
        }

        let (digest, path) = line
            .split_once(char::is_whitespace)
            .with_context(|| format!("line {number} is not a digest followed by a path"))?;
        let path = path.trim_start();

        ensure!(
            is_sha256(digest),
            "line {number} does not begin with a SHA-256 digest"
        );
        ensure!(!path.is_empty(), "line {number} names no file");
        ensure!(
            recorded
                .insert(path.to_string(), digest.to_ascii_lowercase())
                .is_none(),
            "line {number} records {path:?} a second time"
        );
    }

    ensure!(!recorded.is_empty(), "it records no files");
    Ok(recorded)
}

fn parse_domains(contents: &str) -> anyhow::Result<Vec<String>> {
    ensure!(
        contents.ends_with('\n'),
        "a domains-v1 file ends with a newline"
    );
    ensure!(
        !contents.contains('\r'),
        "a domains-v1 file uses newlines, not carriage returns"
    );

    let mut domains: Vec<String> = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let number = index + 1;
        ensure!(
            !line.is_empty(),
            "line {number} is blank; a domains-v1 file has no blank lines, comments, or metadata"
        );
        ensure!(
            valid_catalog_domain(line),
            "line {number} is not a lowercase ASCII hostname: {line:?}"
        );
        if let Some(previous) = domains.last() {
            ensure!(
                previous.as_str() < line,
                "line {number} is out of order or duplicated: {line:?}"
            );
        }
        domains.push(line.to_string());
    }

    ensure!(!domains.is_empty(), "it lists no domains");
    Ok(domains)
}

impl Category {
    fn from_manifest(id: &str, raw: &RawCategory) -> anyhow::Result<Self> {
        ensure!(valid_id(id), "{id:?} is not a valid category id");
        ensure!(!raw.name.trim().is_empty(), "it has no name");
        ensure!(!raw.license.trim().is_empty(), "it names no license");
        ensure!(
            raw.format == CATEGORY_FORMAT,
            "it is in format {:?}; this Walden version reads {CATEGORY_FORMAT:?}",
            raw.format
        );

        let expected_path = category_relative_path(id);
        ensure!(
            raw.path == expected_path,
            "it is recorded at {:?}; a {CATEGORY_FORMAT} distribution keeps it at {expected_path:?}",
            raw.path
        );

        ensure!(is_sha256(&raw.sha256), "its digest is not a SHA-256 digest");
        ensure!(raw.bytes > 0, "it is recorded as empty");
        ensure!(raw.domains > 0, "it is recorded as having no domains");

        Ok(Self {
            id: id.to_string(),
            name: raw.name.clone(),
            description: raw.description.clone(),
            warning: raw
                .warning
                .as_deref()
                .map(str::trim)
                .filter(|warning| !warning.is_empty())
                .map(str::to_string),
            recommended: raw.recommended,
            confidence: raw.confidence.clone(),
            variant: raw.variant.clone(),
            license: raw.license.clone(),
            domains: raw.domains,
            bytes: raw.bytes,
            sha256: raw.sha256.to_ascii_lowercase(),
            relative_path: expected_path,
        })
    }
}

impl Catalog {
    pub fn open<P: Into<PathBuf>>(root: P) -> anyhow::Result<Self> {
        let root = root.into();

        let manifest_path = root.join(MANIFEST_FILE_NAME);
        let manifest_bytes = fs::read(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        let manifest: RawManifest = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("failed to parse {}", manifest_path.display()))?;

        ensure!(
            manifest.format == MANIFEST_FORMAT,
            "{} is in format {:?}; this Walden version reads {MANIFEST_FORMAT:?}",
            manifest_path.display(),
            manifest.format
        );
        ensure!(
            manifest.schema_version == MANIFEST_SCHEMA_VERSION,
            "{} declares schema version {}; this Walden version reads version {MANIFEST_SCHEMA_VERSION}",
            manifest_path.display(),
            manifest.schema_version
        );
        ensure!(
            !manifest.generated_at.trim().is_empty(),
            "{} does not say when it was generated",
            manifest_path.display()
        );
        ensure!(
            !manifest.categories.is_empty(),
            "{} describes no categories",
            manifest_path.display()
        );

        let checksums_path = root.join(CHECKSUMS_FILE_NAME);
        let checksums_contents = fs::read_to_string(&checksums_path)
            .with_context(|| format!("failed to read {}", checksums_path.display()))?;
        let checksums = parse_checksums(&checksums_contents)
            .with_context(|| format!("failed to read {}", checksums_path.display()))?;

        let mut categories = Vec::with_capacity(manifest.categories.len());
        for (id, raw) in &manifest.categories {
            let category = Category::from_manifest(id, raw).with_context(|| {
                format!(
                    "{} describes category {id:?} in a way this Walden version cannot use",
                    manifest_path.display()
                )
            })?;

            let recorded = checksums.get(&category.relative_path).with_context(|| {
                format!(
                    "{} does not record {}, so this snapshot is incomplete",
                    checksums_path.display(),
                    category.relative_path
                )
            })?;
            ensure!(
                *recorded == category.sha256,
                "{} and {} disagree about {}",
                manifest_path.display(),
                checksums_path.display(),
                category.relative_path
            );

            categories.push(category);
        }

        for path in checksums.keys() {
            let id = category_id_of(path).with_context(|| {
                format!("{} records an unexpected file", checksums_path.display())
            })?;
            ensure!(
                manifest.categories.contains_key(id),
                "{} records {path}, which {} does not describe",
                checksums_path.display(),
                manifest_path.display()
            );
        }

        let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
        let version = format!("{}+{}", manifest.generated_at, &manifest_sha256[..8]);

        let domains = categories
            .iter()
            .map(|category| (category.id.clone(), OnceLock::new()))
            .collect();
        let sources = manifest
            .sources
            .iter()
            .map(|(id, raw)| Source {
                id: id.clone(),
                repository: raw.repository.clone(),
                commit: raw.commit.clone(),
                license: raw.license.clone(),
            })
            .collect();

        Ok(Self {
            root,
            version,
            generated_at: manifest.generated_at,
            manifest_sha256,
            categories,
            sources,
            domains,
        })
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn generated_at(&self) -> &str {
        &self.generated_at
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn directory(&self) -> &Path {
        &self.root
    }

    pub fn categories(&self) -> &[Category] {
        &self.categories
    }

    pub fn category(&self, id: &str) -> Option<&Category> {
        self.categories.iter().find(|category| category.id == id)
    }

    pub fn category_ids(&self) -> impl Iterator<Item = &str> {
        self.categories.iter().map(|category| category.id.as_str())
    }

    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    pub fn require(&self, id: &str) -> anyhow::Result<&Category> {
        self.category(id).with_context(|| {
            format!(
                "unknown category {id:?}; available categories: {}",
                self.category_ids().collect::<Vec<_>>().join(", ")
            )
        })
    }

    pub fn domains(&self, id: &str) -> anyhow::Result<&[String]> {
        let category = self.require(id)?;
        let cell = self
            .domains
            .get(id)
            .expect("every manifest category has a domain cell");

        if let Some(domains) = cell.get() {
            return Ok(domains);
        }

        let domains = self.verified_domains(category)?;
        Ok(cell.get_or_init(|| domains))
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        for category in &self.categories {
            self.domains(&category.id)?;
        }
        Ok(())
    }

    fn verified_domains(&self, category: &Category) -> anyhow::Result<Vec<String>> {
        let path = self.root.join(&category.relative_path);
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;

        ensure!(
            bytes.len() as u64 == category.bytes,
            "{} is {} bytes; the manifest records {}",
            path.display(),
            bytes.len(),
            category.bytes
        );

        let digest = hex::encode(Sha256::digest(&bytes));
        ensure!(
            digest == category.sha256,
            "{} does not match the manifest\n  expected {}\n  actual   {digest}",
            path.display(),
            category.sha256
        );

        let contents =
            String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
        let domains = parse_domains(&contents)
            .with_context(|| format!("failed to read {}", path.display()))?;

        ensure!(
            domains.len() == category.domains,
            "{} lists {} domains; the manifest records {}",
            path.display(),
            domains.len(),
            category.domains
        );

        Ok(domains)
    }
}

pub fn search_paths() -> Vec<PathBuf> {
    if let Some(directory) = env::var_os(CATALOG_DIR_ENV) {
        return vec![PathBuf::from(directory)];
    }

    vec![updated_directory(), bundled_directory()]
}

pub fn updated_directory() -> PathBuf {
    env::var_os(CATALOG_CACHE_DIR_ENV)
        .map_or_else(|| PathBuf::from(UPDATED_CATALOG_DIR), PathBuf::from)
}

pub fn bundled_directory() -> PathBuf {
    env::var_os(BUNDLED_CATALOG_DIR_ENV)
        .map_or_else(|| PathBuf::from(BUNDLED_CATALOG_DIR), PathBuf::from)
}

fn open_verified(path: &Path) -> anyhow::Result<Catalog> {
    let catalog = Catalog::open(path)?;
    catalog.verify()?;
    Ok(catalog)
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

fn inspect_cache(path: &Path) -> (CatalogCacheState, Option<Catalog>) {
    match path.try_exists() {
        Ok(false) => return (CatalogCacheState::Absent, None),
        Err(error) => {
            return (
                CatalogCacheState::Invalid {
                    detail: format!("could not inspect the cache: {error}"),
                },
                None,
            );
        }
        Ok(true) => {}
    }

    let manifest = path.join(MANIFEST_FILE_NAME);
    match manifest.try_exists() {
        Ok(false) => {
            return (
                CatalogCacheState::Incomplete {
                    detail: format!("{MANIFEST_FILE_NAME} is missing"),
                },
                None,
            );
        }
        Err(error) => {
            return (
                CatalogCacheState::Invalid {
                    detail: format!("could not inspect {}: {error}", manifest.display()),
                },
                None,
            );
        }
        Ok(true) => {}
    }

    match open_verified(path) {
        Ok(catalog) => (CatalogCacheState::Valid, Some(catalog)),
        Err(error) if error_is_not_found(&error) => (
            CatalogCacheState::Incomplete {
                detail: "a required snapshot file is missing".to_string(),
            },
            None,
        ),
        Err(error) => (
            CatalogCacheState::Invalid {
                detail: format!("{error:#}"),
            },
            None,
        ),
    }
}

// Selects one fully verified snapshot. An explicitly requested directory is
// authoritative and never falls back. Otherwise a bad optional update cache
// falls back to the package snapshot with a structured diagnostic.
pub fn select(explicit_directory: Option<&Path>) -> anyhow::Result<CatalogSelection> {
    let explicit = explicit_directory
        .map(Path::to_path_buf)
        .or_else(|| env::var_os(CATALOG_DIR_ENV).map(PathBuf::from));
    if let Some(path) = explicit {
        let catalog = open_verified(&path)
            .with_context(|| format!("failed to read the catalog at {}", path.display()))?;
        return Ok(CatalogSelection {
            catalog,
            cache_state: None,
        });
    }

    select_installed(updated_directory(), bundled_directory())
}

fn select_installed(
    cache_path: PathBuf,
    bundled_path: PathBuf,
) -> anyhow::Result<CatalogSelection> {
    let (cache_state, cached) = inspect_cache(&cache_path);
    if let Some(catalog) = cached {
        return Ok(CatalogSelection {
            catalog,
            cache_state: Some(cache_state),
        });
    }

    let catalog = open_verified(&bundled_path).with_context(|| {
        format!(
            "failed to read the bundled category catalog at {}",
            bundled_path.display()
        )
    })?;
    Ok(CatalogSelection {
        catalog,
        cache_state: Some(cache_state),
    })
}

// Compatibility entry point for library callers. CLI commands use `select`
// directly so they decide exactly once where a notice is rendered.
pub fn load() -> anyhow::Result<&'static Catalog> {
    static LOADED: OnceLock<Catalog> = OnceLock::new();

    if let Some(catalog) = LOADED.get() {
        return Ok(catalog);
    }

    let selection = select(None).map_err(|error| {
        anyhow::anyhow!(
            "{error:#}\n\nInstall a Walden package to get a catalog, run `walden catalog update` to download one, or set {CATALOG_DIR_ENV} to a walden-list dist/v1 directory."
        )
    })?;
    if let Some(notice) = selection.fallback_notice() {
        eprintln!("Notice: {notice}");
    }
    Ok(LOADED.get_or_init(|| selection.into_catalog()))
}

// Nothing is replaced until the full snapshot verifies in staging.
pub fn update(source: &str) -> anyhow::Result<Catalog> {
    install_from(source, &updated_directory())
}

pub fn install_from(source: &str, destination: &Path) -> anyhow::Result<Catalog> {
    let parent = destination
        .parent()
        .with_context(|| format!("{} has no parent directory", destination.display()))?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} is not a usable directory name", destination.display()))?;

    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    let staging = parent.join(format!(".{name}.incoming-{}", std::process::id()));
    remove_tree(&staging)?;

    let staged = stage(source, &staging);
    if staged.is_err() {
        let _ = remove_tree(&staging);
    }
    staged?;

    swap(&staging, destination).inspect_err(|_| {
        let _ = remove_tree(&staging);
    })?;

    // Read-only modes are applied after the swap: macOS needs write permission
    // on a directory to rename it.
    set_tree_modes(destination, DIRECTORY_MODE, FILE_MODE)?;

    Catalog::open(destination).with_context(|| {
        format!(
            "failed to read the catalog installed at {}",
            destination.display()
        )
    })
}

fn stage(source: &str, staging: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(staging.join(CATEGORY_DIRECTORY))
        .with_context(|| format!("failed to create {}", staging.display()))?;

    for name in [MANIFEST_FILE_NAME, CHECKSUMS_FILE_NAME] {
        fetch::download(&fetch::join(source, name), &staging.join(name))?;
    }

    let checksums_path = staging.join(CHECKSUMS_FILE_NAME);
    let checksums = parse_checksums(
        &fs::read_to_string(&checksums_path)
            .with_context(|| format!("failed to read {}", checksums_path.display()))?,
    )
    .with_context(|| format!("failed to read {}", checksums_path.display()))?;

    for relative_path in checksums.keys() {
        let id = category_id_of(relative_path).with_context(|| {
            format!(
                "{} records a file Walden will not download",
                checksums_path.display()
            )
        })?;
        let destination = staging.join(category_relative_path(id));
        fetch::download(&fetch::join(source, relative_path), &destination)?;
    }

    let catalog = Catalog::open(staging)?;
    catalog.verify()?;
    Ok(())
}

// Two renames with rollback; POSIX has no atomic replace for a populated directory.
fn swap(staging: &Path, destination: &Path) -> anyhow::Result<()> {
    let previous = destination.with_file_name(format!(
        ".{}.previous-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("catalog"),
        std::process::id()
    ));
    remove_tree(&previous)?;

    let replacing = destination.exists();
    if replacing {
        // macOS will not rename a 0555 directory.
        let _ = set_tree_modes(destination, 0o755, 0o644);
        fs::rename(destination, &previous)
            .with_context(|| format!("failed to move {} aside", destination.display()))?;
    }

    if let Err(err) = fs::rename(staging, destination) {
        if replacing {
            let _ = fs::rename(&previous, destination);
        }
        return Err(err).with_context(|| {
            format!(
                "failed to move the verified catalog into {}",
                destination.display()
            )
        });
    }

    remove_tree(&previous)
}

// Children before parents so a read-only directory does not block inner files.
#[cfg(unix)]
pub fn set_tree_modes(path: &Path, directory_mode: u32, file_mode: u32) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;

    if metadata.is_dir() {
        for entry in
            fs::read_dir(path).with_context(|| format!("failed to list {}", path.display()))?
        {
            let entry = entry.with_context(|| format!("failed to list {}", path.display()))?;
            set_tree_modes(&entry.path(), directory_mode, file_mode)?;
        }
    }

    ensure!(
        metadata.is_dir() || metadata.is_file(),
        "{} is neither a file nor a directory",
        path.display()
    );

    let mode = if metadata.is_dir() {
        directory_mode
    } else {
        file_mode
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set the mode of {}", path.display()))
}

#[cfg(not(unix))]
pub fn set_tree_modes(_path: &Path, _directory_mode: u32, _file_mode: u32) -> anyhow::Result<()> {
    Ok(())
}

// Read-only install also blocks deletion; restore write permission first.
fn remove_tree(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let _ = set_tree_modes(path, 0o755, 0o644);
    fs::remove_dir_all(path).with_context(|| format!("failed to remove {}", path.display()))
}

pub fn vendored_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/walden-list/v1")
}

pub fn vendored() -> Catalog {
    let root = vendored_dir();
    Catalog::open(&root).unwrap_or_else(|err| {
        panic!(
            "{err:#}\n\nRun ./scripts/fetch-catalog.sh to vendor the walden-list snapshot \
             assets/catalog.lock pins."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Snapshot {
        root: PathBuf,
    }

    impl Snapshot {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before the Unix epoch")
                .as_nanos();
            let root = env::temp_dir().join(format!(
                "walden-catalog-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(root.join(CATEGORY_DIRECTORY)).unwrap();

            let snapshot = Snapshot { root };
            snapshot.write(&[
                ("social-media", "example.test\nsocial.test\n"),
                ("gambling", "casino.test\n"),
            ]);
            snapshot
        }

        fn write(&self, categories: &[(&str, &str)]) {
            let mut manifest = String::from(
                "{\"format\":\"walden-domain-registry-v1\",\"schema_version\":1,\
                 \"generated_at\":\"2026-07-30T07:17:05Z\",\"categories\":{",
            );
            let mut checksums = String::new();

            for (index, (id, contents)) in categories.iter().enumerate() {
                let relative_path = category_relative_path(id);
                fs::write(self.root.join(&relative_path), contents).unwrap();

                let digest = hex::encode(Sha256::digest(contents.as_bytes()));
                checksums.push_str(&format!("{digest}  {relative_path}\n"));

                if index > 0 {
                    manifest.push(',');
                }
                manifest.push_str(&format!(
                    "\"{id}\":{{\"name\":\"{id}\",\"description\":\"d\",\"license\":\"MIT\",\
                     \"format\":\"domains-v1\",\"path\":\"{relative_path}\",\"sha256\":\"{digest}\",\
                     \"bytes\":{},\"domains\":{},\"recommended\":true,\"confidence\":\"high\"}}",
                    contents.len(),
                    contents.lines().count()
                ));
            }
            manifest.push_str("}}");

            fs::write(self.root.join(MANIFEST_FILE_NAME), manifest).unwrap();
            fs::write(self.root.join(CHECKSUMS_FILE_NAME), checksums).unwrap();
        }

        fn open(&self) -> anyhow::Result<Catalog> {
            Catalog::open(&self.root)
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }
    }

    impl Drop for Snapshot {
        fn drop(&mut self) {
            let _ = remove_tree(&self.root);
        }
    }

    #[test]
    fn reads_a_manifest_and_the_domains_it_describes() {
        let snapshot = Snapshot::new("read");
        let catalog = snapshot.open().unwrap();

        assert_eq!(
            catalog.category_ids().collect::<Vec<_>>(),
            ["gambling", "social-media"]
        );
        assert_eq!(
            catalog.domains("social-media").unwrap(),
            ["example.test", "social.test"]
        );
        assert_eq!(catalog.category("gambling").unwrap().domains, 1);
        assert!(catalog.category("missing").is_none());
    }

    #[test]
    fn the_version_is_derived_from_the_manifest_and_changes_with_it() {
        let snapshot = Snapshot::new("version");
        let first = snapshot.open().unwrap();

        assert!(first.version().starts_with("2026-07-30T07:17:05Z+"));
        assert_eq!(first.version(), snapshot.open().unwrap().version());

        snapshot.write(&[("social-media", "example.test\n")]);
        let changed = snapshot.open().unwrap();
        assert_ne!(first.version(), changed.version());
        assert_eq!(changed.generated_at(), first.generated_at());
    }

    #[test]
    fn an_unknown_category_names_the_ones_that_exist() {
        let snapshot = Snapshot::new("unknown");
        let catalog = snapshot.open().unwrap();

        let err = catalog.domains("missing").unwrap_err().to_string();
        assert!(err.contains("unknown category"), "{err}");
        assert!(err.contains("gambling, social-media"), "{err}");
    }

    #[test]
    fn a_tampered_category_file_is_refused_rather_than_shortened() {
        let snapshot = Snapshot::new("tampered-domains");
        fs::write(
            snapshot.path("categories/social-media.txt"),
            "example.test\n",
        )
        .unwrap();

        let err = snapshot
            .open()
            .unwrap()
            .domains("social-media")
            .unwrap_err()
            .to_string();
        assert!(err.contains("bytes"), "{err}");
    }

    #[test]
    fn a_category_file_of_the_right_length_still_has_to_match_its_digest() {
        let snapshot = Snapshot::new("tampered-digest");
        // The same byte count, so only the digest can catch it.
        fs::write(
            snapshot.path("categories/social-media.txt"),
            "examples.test\nsocial.tes\n",
        )
        .unwrap();

        let err = snapshot
            .open()
            .unwrap()
            .domains("social-media")
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match the manifest"), "{err}");
    }

    #[test]
    fn a_manifest_and_checksums_that_disagree_are_refused() {
        let snapshot = Snapshot::new("disagreeing");
        let mut checksums = fs::read_to_string(snapshot.path(CHECKSUMS_FILE_NAME)).unwrap();
        checksums = checksums.replacen('0', "1", 1).replacen('1', "2", 1);
        fs::write(snapshot.path(CHECKSUMS_FILE_NAME), checksums).unwrap();

        let err = snapshot.open().unwrap_err().to_string();
        assert!(err.contains("disagree about"), "{err}");
    }

    #[test]
    fn an_incomplete_snapshot_is_refused() {
        let missing_file = Snapshot::new("missing-file");
        fs::remove_file(missing_file.path("categories/gambling.txt")).unwrap();
        assert!(missing_file.open().unwrap().domains("gambling").is_err());

        let missing_record = Snapshot::new("missing-record");
        let checksums = fs::read_to_string(missing_record.path(CHECKSUMS_FILE_NAME)).unwrap();
        let kept: String = checksums
            .lines()
            .filter(|line| !line.contains("gambling"))
            .map(|line| format!("{line}\n"))
            .collect();
        fs::write(missing_record.path(CHECKSUMS_FILE_NAME), kept).unwrap();

        let err = missing_record.open().unwrap_err().to_string();
        assert!(err.contains("incomplete"), "{err}");

        let missing_manifest = Snapshot::new("missing-manifest");
        fs::remove_file(missing_manifest.path(MANIFEST_FILE_NAME)).unwrap();
        assert!(missing_manifest.open().is_err());
    }

    #[test]
    fn a_file_the_manifest_does_not_describe_is_refused() {
        let snapshot = Snapshot::new("undescribed");
        let mut checksums = fs::read_to_string(snapshot.path(CHECKSUMS_FILE_NAME)).unwrap();
        checksums.push_str(&format!("{}  categories/extra.txt\n", "a".repeat(64)));
        fs::write(snapshot.path(CHECKSUMS_FILE_NAME), checksums).unwrap();

        let err = snapshot.open().unwrap_err().to_string();
        assert!(err.contains("does not describe"), "{err}");
    }

    #[test]
    fn only_the_declared_distribution_format_is_read() {
        let snapshot = Snapshot::new("format");
        let manifest = fs::read_to_string(snapshot.path(MANIFEST_FILE_NAME))
            .unwrap()
            .replace("\"schema_version\":1", "\"schema_version\":2");
        fs::write(snapshot.path(MANIFEST_FILE_NAME), manifest).unwrap();

        let err = snapshot.open().unwrap_err().to_string();
        assert!(err.contains("schema version 2"), "{err}");
    }

    #[test]
    fn domains_must_be_lowercase_sorted_and_deduplicated() {
        assert_eq!(parse_domains("a.test\nb.test\n").unwrap().len(), 2);
        assert!(parse_domains("under_score.test\n").is_ok());

        for rejected in [
            "b.test\na.test\n",     // out of order
            "a.test\na.test\n",     // duplicated
            "A.test\n",             // not lowercase
            "a.test",               // no trailing newline
            "a.test\n\nb.test\n",   // blank line
            "# comment\na.test\n",  // metadata
            "a.test\r\nb.test\r\n", // carriage returns
            "0.0.0.0 a.test\n",     // hosts format
            "-a.test\n",            // label boundary
            "a..test\n",            // empty label
            "a.test.\n",            // trailing dot
            "\n",                   // nothing at all
        ] {
            assert!(parse_domains(rejected).is_err(), "accepted {rejected:?}");
        }
    }

    #[test]
    fn the_pinned_walden_list_snapshot_verifies_in_full() {
        let catalog = vendored();

        assert!(catalog.version().contains('+'));
        assert!(catalog.category("social-media").is_some());
        assert!(!catalog.sources().is_empty());
        catalog.verify().unwrap();

        for category in catalog.categories() {
            assert_eq!(
                catalog.domains(&category.id).unwrap().len(),
                category.domains
            );
        }
    }

    #[test]
    fn a_catalog_directory_is_searched_before_the_installed_ones() {
        if env::var_os(CATALOG_DIR_ENV).is_some() {
            assert_eq!(search_paths().len(), 1);
        } else {
            assert_eq!(search_paths(), [updated_directory(), bundled_directory()]);
        }
    }

    #[test]
    fn cache_state_distinguishes_absent_incomplete_invalid_and_valid() {
        let cache = unique_dir("missing-optional-cache");
        assert!(!cache.exists());
        assert!(matches!(
            inspect_cache(&cache),
            (CatalogCacheState::Absent, None)
        ));

        fs::create_dir_all(&cache).unwrap();
        let (state, catalog) = inspect_cache(&cache);
        assert!(catalog.is_none());
        assert!(matches!(state, CatalogCacheState::Incomplete { .. }));
        remove_tree(&cache).unwrap();

        let invalid = unique_dir("invalid-optional-cache");
        fs::create_dir_all(&invalid).unwrap();
        fs::write(invalid.join(MANIFEST_FILE_NAME), "not json\n").unwrap();
        let (state, catalog) = inspect_cache(&invalid);
        assert!(catalog.is_none());
        assert!(matches!(state, CatalogCacheState::Invalid { .. }));
        remove_tree(&invalid).unwrap();

        let valid = Snapshot::new("valid-optional-cache");
        let (state, catalog) = inspect_cache(&valid.root);
        assert_eq!(state, CatalogCacheState::Valid);
        assert_eq!(catalog.unwrap().directory(), valid.root.as_path());
    }

    #[test]
    fn an_incomplete_update_uses_the_verified_bundle_with_one_concise_notice() {
        let cache = unique_dir("incomplete-fallback");
        fs::create_dir_all(&cache).unwrap();
        let bundled = Snapshot::new("bundled-fallback");

        let selection = select_installed(cache.clone(), bundled.root.clone()).unwrap();
        assert!(matches!(
            selection.cache_state(),
            Some(CatalogCacheState::Incomplete { .. })
        ));
        assert_eq!(selection.catalog().directory(), bundled.root.as_path());
        let notice = selection.fallback_notice().unwrap();
        assert!(notice.contains("Using bundled catalog"), "{notice}");
        assert!(notice.contains("incomplete downloaded update"), "{notice}");
        assert!(notice.contains("sudo walden catalog update"), "{notice}");
        assert!(!notice.contains("manifest.json"), "{notice}");
        assert!(!notice.contains("os error"), "{notice}");
        remove_tree(&cache).unwrap();
    }

    #[test]
    fn a_tampered_update_is_invalid_and_falls_back_before_use() {
        let cache = Snapshot::new("tampered-cache");
        fs::write(
            cache.path("categories/social-media.txt"),
            "examples.test\nsocial.tes\n",
        )
        .unwrap();
        let bundled = Snapshot::new("bundled-for-invalid-cache");

        let selection = select_installed(cache.root.clone(), bundled.root.clone()).unwrap();
        assert!(matches!(
            selection.cache_state(),
            Some(CatalogCacheState::Invalid { .. })
        ));
        assert_eq!(selection.catalog().directory(), bundled.root.as_path());
        let notice = selection.fallback_notice().unwrap();
        assert!(notice.contains("invalid downloaded update"), "{notice}");
        assert!(!notice.contains("does not match the manifest"), "{notice}");
    }

    #[test]
    fn an_absent_update_uses_the_bundle_without_a_notice() {
        let cache = unique_dir("absent-fallback");
        let bundled = Snapshot::new("bundled-for-absent-cache");

        let selection = select_installed(cache, bundled.root.clone()).unwrap();
        assert_eq!(selection.cache_state(), Some(&CatalogCacheState::Absent));
        assert_eq!(selection.catalog().directory(), bundled.root.as_path());
        assert!(selection.fallback_notice().is_none());
    }

    fn unique_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "walden-catalog-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    fn file_url(path: &Path) -> String {
        format!("file://{}", path.display())
    }

    #[test]
    fn a_verified_snapshot_replaces_the_updated_catalog() {
        let source = Snapshot::new("update-source");
        let destination = unique_dir("update-dest");

        let catalog = install_from(&file_url(&source.root), &destination).unwrap();
        assert_eq!(catalog.directory(), destination.as_path());
        assert_eq!(
            catalog.domains("social-media").unwrap(),
            ["example.test", "social.test"]
        );

        #[cfg(unix)]
        {
            let file_mode = fs::metadata(destination.join(MANIFEST_FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let dir_mode = fs::metadata(&destination).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, FILE_MODE);
            assert_eq!(dir_mode, DIRECTORY_MODE);
        }

        let _ = remove_tree(&destination);
    }

    #[test]
    fn a_failed_update_leaves_the_existing_cache_untouched() {
        let source = Snapshot::new("update-good");
        let destination = unique_dir("update-keep");
        let installed = install_from(&file_url(&source.root), &destination).unwrap();
        let previous = installed.version().to_string();

        fs::write(source.path("categories/social-media.txt"), "evil.test\n").unwrap();
        let err = install_from(&file_url(&source.root), &destination)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bytes") || err.contains("does not match") || err.contains("failed"),
            "{err}"
        );

        let still = Catalog::open(&destination).unwrap();
        assert_eq!(still.version(), previous);
        assert_eq!(
            still.domains("social-media").unwrap(),
            ["example.test", "social.test"]
        );

        let _ = remove_tree(&destination);
    }

    #[test]
    fn a_failed_first_update_does_not_create_the_destination() {
        let destination = unique_dir("update-missing");
        assert!(install_from("file:///no/such/walden-catalog", &destination).is_err());
        assert!(!destination.exists());
    }
}
