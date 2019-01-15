//
//  Root filesystem, only shows logged in users' homedir.
//
use std;
use std::path::Path;
use libc::uid_t;
use webdav_handler::webpath::WebPath;
use webdav_handler::fs::*;

use crate::quotafs::QuotaFs;

#[derive(Debug,Clone)]
pub struct RootFs {
    user:       String,
    fs:         QuotaFs,
}

impl RootFs {
    pub fn new<P: AsRef<Path> + Clone>(user: String, base: P, public: bool, user_uid: uid_t) -> Box<RootFs> {
        Box::new(RootFs{
            user:   user,
            fs:     *QuotaFs::new(base, user_uid, public),
        })
    }
}

impl DavFileSystem for RootFs {

    fn metadata(&self, _path: &WebPath) -> FsResult<Box<DavMetaData>> {
        let path = WebPath::from_str("/", "").unwrap();
        self.fs.metadata(&path)
    }

    fn read_dir(&self, path: &WebPath) -> FsResult<Box<DavReadDir>> {
        let mut v = Vec::new();
        v.push(RootFsDirEntry{
            name:   self.user.clone(),
            meta:   self.fs.metadata(path),
        });
        Ok(Box::new(RootFsReadDir{
            iterator:   v.into_iter(),
        }))
    }

    fn open(&self, _path: &WebPath, _options: OpenOptions) -> FsResult<Box<DavFile>> {
        Err(FsError::NotImplemented)
    }

    fn get_quota(&self) -> FsResult<(u64, Option<u64>)> {
        self.fs.get_quota()
    }
}

#[derive(Debug)]
struct RootFsReadDir {
    iterator:   std::vec::IntoIter<RootFsDirEntry>
}

//impl DavReadDir for RootFsReadDir {}

impl Iterator for RootFsReadDir {
    type Item = Box<DavDirEntry>;

    fn next(&mut self) -> Option<Box<DavDirEntry>> {
        match self.iterator.next() {
            None => return None,
            Some(entry) => Some(Box::new(entry)),
        }
    }
}

#[derive(Debug)]
struct RootFsDirEntry {
    meta:       FsResult<Box<DavMetaData>>,
    name:       String,
}

impl DavDirEntry for RootFsDirEntry {
    fn metadata(&self) -> FsResult<Box<DavMetaData>> {
        self.meta.clone()
    }

    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }

    fn is_dir(&self) -> FsResult<bool> {
        Ok(true)
    }
}

