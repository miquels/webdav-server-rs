//
//  Virtual Root filesystem for PROPFIND.
//
//  Shows "/" and "/user".
//
use std;
use std::path::Path;
use std::pin::Pin;

use futures03::{FutureExt, Stream};

use webdav_handler::fs::*;
use webdav_handler::webpath::WebPath;

use crate::userfs::UserFs;

#[derive(Clone)]
pub struct RootFs {
    user: String,
    fs:   UserFs,
}

impl RootFs {
    pub fn new<P>(dir: P, user: String, ugid: Option<(u32, u32)>) -> Box<RootFs>
    where P: AsRef<Path> + Clone {
        Box::new(RootFs {
            user: user,
            fs:   *UserFs::new(dir, ugid, false, false, true),
        })
    }
}

impl DavFileSystem for RootFs {
    // Only allow "/" or "/user", for both return the metadata of the UserFs root.
    fn metadata<'a>(&'a self, path: &'a WebPath) -> FsFuture<Box<DavMetaData>> {
        async move {
            let b = path.as_bytes();
            if b != b"/" && &b[1..] != self.user.as_bytes() {
                return Err(FsError::NotFound);
            }
            let path = WebPath::from_str("/", "").unwrap();
            self.fs.metadata(&path).await
        }
            .boxed()
    }

    // Only return one entry: "user".
    fn read_dir<'a>(
        &'a self,
        path: &'a WebPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<Pin<Box<Stream<Item = Box<DavDirEntry>> + Send>>>
    {
        Box::pin(
            async move {
                let mut v = Vec::new();
                if self.user != "" {
                    v.push(RootFsDirEntry {
                        name: self.user.clone(),
                        meta: self.fs.metadata(path).await,
                    });
                }
                let strm = futures03::stream::iter(RootFsReadDir {
                    iterator: v.into_iter(),
                });
                Ok(Box::pin(strm) as Pin<Box<Stream<Item = Box<DavDirEntry>> + Send>>)
            },
        )
    }

    // cannot open any files.
    fn open(&self, _path: &WebPath, _options: OpenOptions) -> FsFuture<Box<DavFile>> {
        Box::pin(futures03::future::ready(Err(FsError::NotImplemented)))
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
    meta: FsResult<Box<DavMetaData>>,
    name: String,
}

impl DavDirEntry for RootFsDirEntry {
    fn metadata(&self) -> FsFuture<Box<DavMetaData>> {
        Box::pin(futures03::future::ready(self.meta.clone()))
    }

    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }

    fn is_dir(&self) -> FsFuture<bool> {
        Box::pin(futures03::future::ready(Ok(true)))
    }
}
