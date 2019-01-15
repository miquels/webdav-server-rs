use std::path::{Path,PathBuf};
use std::time::Duration;

use webdav_handler::webpath::WebPath;
use webdav_handler::fs::*;
use webdav_handler::localfs::LocalFs;

use fs_quota::*;
use crate::cache;

lazy_static! {
    static ref QCACHE: cache::Cache<PathBuf, FsQuota> = cache::Cache::new().maxage(Duration::new(30, 0));
}

#[derive(Debug,Clone)]
pub struct QuotaFs {
    fs:         LocalFs,
    basedir:    PathBuf,
    base_uid:   u32,
}

impl QuotaFs {
    pub fn new<P: AsRef<Path>>(base: P, uid: u32, public: bool) -> Box<QuotaFs> {
        Box::new(QuotaFs{
            basedir:    base.as_ref().to_owned(),
            fs:         *LocalFs::new(base, public),
            base_uid:   uid,
        })
    }
}

impl DavFileSystem for QuotaFs {

    #[inline]
    fn metadata(&self, path: &WebPath) -> FsResult<Box<DavMetaData>> {
        self.fs.metadata(path)
    }

    fn symlink_metadata(&self, path: &WebPath) -> FsResult<Box<DavMetaData>> {
        self.fs.symlink_metadata(path)
    }

    fn read_dir(&self, path: &WebPath) -> FsResult<Box<DavReadDir>> {
        self.fs.read_dir(path)
    }

    fn open(&self, path: &WebPath, options: OpenOptions) -> FsResult<Box<DavFile>> {
        self.fs.open(path, options)
    }

    fn create_dir(&self, path: &WebPath) -> FsResult<()> {
        self.fs.create_dir(path)
    }

    fn remove_dir(&self, path: &WebPath) -> FsResult<()> {
        self.fs.remove_dir(path)
    }

    fn remove_file(&self, path: &WebPath) -> FsResult<()> {
        self.fs.remove_file(path)
    }

    fn rename(&self, from: &WebPath, to: &WebPath) -> FsResult<()> {
        self.fs.rename(from, to)
    }

    fn copy(&self, from: &WebPath, to: &WebPath) -> FsResult<()> {
        self.fs.copy(from, to)
    }

    fn get_quota(&self) -> FsResult<(u64, Option<u64>)> {
        let mut key = self.basedir.clone();
        key.push(&self.base_uid.to_string());
        let r = match QCACHE.get(&key) {
            Some(r) => {
                debug!("get_quota for {:?}: from cache", key);
                r
            },
            None => {
                let path = &self.basedir;
                let r = FsQuota::check(path)
                    .or_else(|e| if e == FqError::NoQuota { FsQuota::system(path) } else { Err(e) })
                    .map_err(|_| FsError::GeneralFailure)?;
                debug!("get_quota for {:?}: insert to cache", key);
                QCACHE.insert(key, r)
            },
        };
        Ok((r.bytes_used, r.bytes_limit))
    }
}
