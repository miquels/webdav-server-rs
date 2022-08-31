use std::any::Any;
use std::path::{Path, PathBuf};

use webdav_handler::davpath::DavPath;
use webdav_handler::fs::*;
use webdav_handler::localfs::LocalFs;

use crate::suid::UgidSwitch;

#[derive(Clone)]
pub struct UserFs {
    pub fs:  LocalFs,
    basedir: PathBuf,
    uid:     u32,
}

impl UserFs {
    pub fn new(
        dir: impl AsRef<Path>,
        target_creds: Option<(u32, u32, &[u32])>,
        public: bool,
        case_insensitive: bool,
        macos: bool,
    ) -> Box<UserFs>
    {
        // uid is used for quota() calls.
        let uid = target_creds.as_ref().map(|ugid| ugid.0).unwrap_or(0);

        // set up the LocalFs hooks for uid switching.
        let switch = UgidSwitch::new(target_creds.clone());
        let blocking_guard = Box::new(move || Box::new(switch.guard()) as Box<dyn Any>);

        Box::new(UserFs {
            basedir: dir.as_ref().to_path_buf(),
            fs:      *LocalFs::new_with_fs_access_guard(
                dir,
                public,
                case_insensitive,
                macos,
                Some(blocking_guard),
            ),
            uid:     uid,
        })
    }
}

impl DavFileSystem for UserFs {
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<Box<dyn DavMetaData>> {
        self.fs.metadata(path)
    }

    fn symlink_metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<Box<dyn DavMetaData>> {
        self.fs.symlink_metadata(path)
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        meta: ReadDirMeta,
    ) -> FsFuture<FsStream<Box<dyn DavDirEntry>>>
    {
        self.fs.read_dir(path, meta)
    }

    fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions) -> FsFuture<Box<dyn DavFile>> {
        self.fs.open(path, options)
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<()> {
        self.fs.create_dir(path)
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<()> {
        self.fs.remove_dir(path)
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<()> {
        self.fs.remove_file(path)
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<()> {
        self.fs.rename(from, to)
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<()> {
        self.fs.copy(from, to)
    }

    #[cfg(all(not(windows), feature = "quota"))]
    fn get_quota<'a>(&'a self) -> FsFuture<(u64, Option<u64>)> {
        use crate::cache;
        use fs_quota::*;
        use futures::future::FutureExt;
        use std::time::Duration;

        lazy_static::lazy_static! {
            static ref QCACHE: cache::Cache<PathBuf, FsQuota> = cache::Cache::new().maxage(Duration::new(30, 0));
        }

        async move {
            let mut key = self.basedir.clone();
            key.push(&self.uid.to_string());
            let r = match QCACHE.get(&key) {
                Some(r) => {
                    debug!("get_quota for {:?}: from cache", key);
                    r
                },
                None => {
                    let path = self.basedir.clone();
                    let uid = self.uid;
                    let r = self
                        .fs
                        .blocking(move || {
                            FsQuota::check(&path, Some(uid)).map_err(|_| FsError::GeneralFailure)
                        })
                        .await?;
                    debug!("get_quota for {:?}: insert to cache", key);
                    QCACHE.insert(key, r)
                },
            };
            Ok((r.bytes_used, r.bytes_limit))
        }
        .boxed()
    }
}
