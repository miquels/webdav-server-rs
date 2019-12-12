//
//  Virtual Root filesystem for PROPFIND.
//
//  Shows "/" and "/user".
//
use std;
use std::path::Path;

use futures::future::{self, FutureExt};
use webdav_handler::davpath::DavPath;
use webdav_handler::fs::*;

use crate::userfs::UserFs;

#[derive(Clone)]
pub struct RootFs {
    user: String,
    fs:   UserFs,
}

impl RootFs {
    pub fn new<P>(dir: P, user: Option<String>, ugid: Option<(u32, u32)>) -> Box<RootFs>
    where P: AsRef<Path> + Clone {
        Box::new(RootFs {
            user: user.unwrap_or("".to_string()),
            fs:   *UserFs::new(dir, ugid, false, false, true),
        })
    }
}

impl DavFileSystem for RootFs {
    // Only allow "/" or "/user", for both return the metadata of the UserFs root.
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<Box<dyn DavMetaData>> {
        async move {
            let b = path.as_bytes();
            if b != b"/" && &b[1..] != self.user.as_bytes() {
                return Err(FsError::NotFound);
            }
            let path = DavPath::new("/").unwrap();
            self.fs.metadata(&path).await
        }
        .boxed()
    }

    // Only return one entry: "user".
    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<FsStream<Box<dyn DavDirEntry>>>
    {
        Box::pin(async move {
            let mut v = Vec::new();
            if self.user != "" {
                v.push(RootFsDirEntry {
                    name: self.user.clone(),
                    meta: self.fs.metadata(path).await,
                });
            }
            let strm = futures::stream::iter(RootFsReadDir {
                iterator: v.into_iter(),
            });
            Ok(Box::pin(strm) as FsStream<Box<dyn DavDirEntry>>)
        })
    }

    // cannot open any files.
    fn open(&self, _path: &DavPath, _options: OpenOptions) -> FsFuture<Box<dyn DavFile>> {
        Box::pin(future::ready(Err(FsError::NotImplemented)))
    }

    // forward quota.
    fn get_quota(&self) -> FsFuture<(u64, Option<u64>)> {
        self.fs.get_quota()
    }
}

#[derive(Debug)]
struct RootFsReadDir {
    iterator: std::vec::IntoIter<RootFsDirEntry>,
}

impl Iterator for RootFsReadDir {
    type Item = Box<dyn DavDirEntry>;

    fn next(&mut self) -> Option<Box<dyn DavDirEntry>> {
        match self.iterator.next() {
            None => return None,
            Some(entry) => Some(Box::new(entry)),
        }
    }
}

#[derive(Debug)]
struct RootFsDirEntry {
    meta: FsResult<Box<dyn DavMetaData>>,
    name: String,
}

impl DavDirEntry for RootFsDirEntry {
    fn metadata(&self) -> FsFuture<Box<dyn DavMetaData>> {
        Box::pin(future::ready(self.meta.clone()))
    }

    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }

    fn is_dir(&self) -> FsFuture<bool> {
        Box::pin(future::ready(Ok(true)))
    }
}
