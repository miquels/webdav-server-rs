use std::any::Any;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::FutureExt;
use webdav_handler::fs::*;
use webdav_handler::localfs::LocalFs;
use webdav_handler::webpath::WebPath;

use crate::cache;
use crate::suid::UgidSwitch;
use fs_quota::*;

lazy_static! {
    static ref QCACHE: cache::Cache<PathBuf, FsQuota> = cache::Cache::new().maxage(Duration::new(30, 0));
}

#[derive(Clone)]
pub struct UserFs {
    pub fs:     LocalFs,
    basedir:    PathBuf,
    uid:        u32,
}

impl UserFs {
    pub fn new(
        dir: impl AsRef<Path>,
        target_ugid: Option<(u32, u32)>,
        public: bool,
        case_insensitive: bool,
        macos: bool,
    ) -> Box<UserFs>
    {
        // uid is used for quota() calls.
        let uid = target_ugid.as_ref().map(|ugid| ugid.0).unwrap_or(0);

        // set up the LocalFs hooks for uid switching.
        let switch = UgidSwitch::new(target_ugid.clone());
        let blocking_guard = Box::new(move || Box::new(switch.guard()) as Box<dyn Any>);

        Box::new(UserFs {
            basedir:    dir.as_ref().to_path_buf(),
            fs:         *LocalFs::new_with_fs_access_guard(
                dir,
                public,
                case_insensitive,
                macos,
                Some(blocking_guard),
            ),
            uid:        uid,
        })
    }
}

impl DavFileSystem for UserFs {
    fn metadata<'a>(&'a self, path: &'a WebPath) -> FsFuture<Box<dyn DavMetaData>> {
        self.fs.metadata(path)
    }

    fn symlink_metadata<'a>(&'a self, path: &'a WebPath) -> FsFuture<Box<dyn DavMetaData>> {
        self.fs.symlink_metadata(path)
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a WebPath,
        meta: ReadDirMeta,
    ) -> FsFuture<FsStream<Box<dyn DavDirEntry>>>
    {
        self.fs.read_dir(path, meta)
    }

    fn open<'a>(&'a self, path: &'a WebPath, options: OpenOptions) -> FsFuture<Box<dyn DavFile>> {
        self.fs.open(path, options)
    }

    fn create_dir<'a>(&'a self, path: &'a WebPath) -> FsFuture<()> {
        self.fs.create_dir(path)
    }

    fn remove_dir<'a>(&'a self, path: &'a WebPath) -> FsFuture<()> {
        self.fs.remove_dir(path)
    }

    fn remove_file<'a>(&'a self, path: &'a WebPath) -> FsFuture<()> {
        self.fs.remove_file(path)
    }

    fn rename<'a>(&'a self, from: &'a WebPath, to: &'a WebPath) -> FsFuture<()> {
        self.fs.rename(from, to)
    }

    fn copy<'a>(&'a self, from: &'a WebPath, to: &'a WebPath) -> FsFuture<()> {
        self.fs.copy(from, to)
    }

    fn get_quota<'a>(&'a self) -> FsFuture<(u64, Option<u64>)> {
        self.fs.blocking(move || {
            let mut key = self.basedir.clone();
            key.push(&self.uid.to_string());
            let r = match QCACHE.get(&key) {
                Some(r) => {
                    debug!("get_quota for {:?}: from cache", key);
                    r
                },
                None => {
                    let path = &self.basedir;
                    let r = FsQuota::check(path, Some(self.uid))
                        .map_err(|_| FsError::GeneralFailure)?;
                    debug!("get_quota for {:?}: insert to cache", key);
                    QCACHE.insert(key, r)
                },
            };
            Ok((r.bytes_used, r.bytes_limit))
        }).boxed()
    }
}
