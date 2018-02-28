//
//  Simple implementation of a DavFileSystem, basically
//  a 1:1 mapping of the std::fs interface.
//
use std::path::{Path,PathBuf};
use std::time::Duration;

use std::os::raw::c_int;
use libc::{uid_t,gid_t};

use fs_quota::*;

use webdav_handler::webpath::WebPath;
use webdav_handler::fs::*;
use webdav_handler::localfs;

use cache;

extern {
     fn c_setresuid(real: uid_t, effective: uid_t, saved: uid_t) -> c_int;
     fn c_setresgid(real: gid_t, effective: gid_t, saved: gid_t) -> c_int;
}

lazy_static! {
    static ref QCACHE: cache::Cache<PathBuf, FsQuota> = cache::Cache::new().maxage(Duration::new(30, 0));
}

#[derive(Debug,Clone)]
pub struct SuidFs {
    user_uid:   uid_t,
    user_gid:   gid_t,
    base_uid:   uid_t,
    base_gid:   gid_t,
    basedir:    PathBuf,
    fs:         Box<localfs::LocalFs>,
}

impl SuidFs {
    pub fn new<P: AsRef<Path> + Clone>(base: P, public: bool, user_uid: uid_t, user_gid: gid_t, base_uid: uid_t, base_gid: gid_t) -> Box<SuidFs> {
        let base = base.as_ref();
        Box::new(SuidFs{
            fs: localfs::LocalFs::new(base, public),
            basedir:    base.to_path_buf(),
            user_uid:   user_uid,
            user_gid:   user_gid,
            base_uid:   base_uid,
            base_gid:   base_gid,
        })
    }
    fn switch_uid(&self) -> FsResult<UidSwitcher> {
        UidSwitcher::new(self.user_uid, self.user_gid, self.base_uid, self.base_gid)
    }
}

#[derive(Debug)]
pub struct UidSwitcher {
    base_uid:   uid_t,
    base_gid:   gid_t,
}

impl UidSwitcher {
    pub fn new(user_uid: uid_t, user_gid: gid_t, base_uid: uid_t, base_gid: gid_t) -> FsResult<UidSwitcher> {
        // must first switch to root....
        if unsafe { c_setresuid(base_uid, 0, 0xffffffff) } != 0 {
            debug!("enter suidfs: failed to resuid({}, 0, -1)", base_uid);
            return Err(FsError::GeneralFailure);
        }
        // so we can setresgid ...
        if unsafe { c_setresgid(base_gid, user_gid, 0xffffffff) } != 0 {
            // if that fails, undo setuid .. if THAT fails, panic.
            debug!("enter suidfs: failed to resgid({}, {}, -1)", base_gid, user_gid);
            if unsafe { c_setresuid(base_uid, base_uid, 0xffffffff) } != 0 {
                panic!("UidSwitcher: enter suidfs: cannot switch uid back to {}", base_uid);
            }
            return Err(FsError::GeneralFailure);
        }
        if unsafe { c_setresuid(base_uid, user_uid, 0xffffffff) } != 0 {
            debug!("enter suidfs: failed to resuid({}, {}, -1)", base_uid, user_uid);
            // undo the lot ... switch to root, switch back gid, switch back uid..
            if unsafe { c_setresuid(base_uid, 0, 0xffffffff) } != 0 {
                panic!("UidSwitcher: enter/fail suidfs: cannot switch gid back to {}", base_gid);
            }
            if unsafe { c_setresgid(base_gid, base_gid, 0xffffffff) } != 0 {
                panic!("UidSwitcher: enter/fail suidfs: cannot switch gid back to {}", base_gid);
            }
            if unsafe { c_setresuid(base_uid, base_uid, 0xffffffff) } != 0 {
                panic!("UidSwitcher: enter/fail suidfs: cannot switch uid back to {}", base_uid);
            }
            return Err(FsError::GeneralFailure);
        }
        Ok(UidSwitcher{
            base_uid: base_uid,
            base_gid: base_gid,
        })
    }
}

impl Drop for UidSwitcher {
    fn drop(&mut self) {
        if unsafe { c_setresuid(self.base_uid, self.base_uid, 0xffffffff) } != 0 {
            debug!("exit suidfs: failed to resuid({}, {}, -1)", self.base_uid, self.base_uid);
            panic!("UidSwitcher: exit suidfs: cannot switch uid back to {}", self.base_uid);
        }
        if unsafe { c_setresgid(self.base_gid, self.base_gid, 0xffffffff) } != 0 {
            debug!("exit suidfs: failed to resgid({}, {}, -1)", self.base_gid, self.base_gid);
            panic!("UidSwitcher: exit suidfs: cannot switch gid back to {}", self.base_gid);
        }
    }
}

impl DavFileSystem for SuidFs {

    fn metadata(&self, path: &WebPath) -> FsResult<Box<DavMetaData>> {
        let _guard = self.switch_uid()?;
        self.fs.metadata(path)
    }

    fn symlink_metadata(&self, path: &WebPath) -> FsResult<Box<DavMetaData>> {
        let _guard = self.switch_uid()?;
        self.fs.symlink_metadata(path)
    }

    fn read_dir(&self, path: &WebPath) -> FsResult<Box<DavReadDir<Item=Box<DavDirEntry>>>> {
        let _guard = self.switch_uid()?;
        let rd = self.fs.read_dir(path)?;
        Ok(Box::new(SuidFsReadDir{
            iterator:   rd,
            user_uid:   self.user_uid,
            user_gid:   self.user_gid,
            base_uid:   self.base_uid,
            base_gid:   self.base_gid,
        }))
    }

    fn open(&self, path: &WebPath, options: OpenOptions) -> FsResult<Box<DavFile>> {
        let _guard = self.switch_uid()?;
        self.fs.open(path, options)
    }

    fn create_dir(&self, path: &WebPath) -> FsResult<()> {
        let _guard = self.switch_uid()?;
        self.fs.create_dir(path)
    }

    fn remove_dir(&self, path: &WebPath) -> FsResult<()> {
        let _guard = self.switch_uid()?;
        self.fs.remove_dir(path)
    }

    fn remove_file(&self, path: &WebPath) -> FsResult<()> {
        let _guard = self.switch_uid()?;
        self.fs.remove_file(path)
    }

    fn rename(&self, from: &WebPath, to: &WebPath) -> FsResult<()> {
        let _guard = self.switch_uid()?;
        self.fs.rename(from, to)
    }

    fn copy(&self, from: &WebPath, to: &WebPath) -> FsResult<()> {
        let _guard = self.switch_uid()?;
        self.fs.rename(from, to)
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
                let _guard = UidSwitcher::new(0, 0, self.base_uid, self.base_gid)?;
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

#[derive(Debug)]
struct SuidFsReadDir {
    iterator:   Box<DavReadDir<Item=Box<DavDirEntry>>>,
    user_uid:   uid_t,
    user_gid:   gid_t,
    base_uid:   uid_t,
    base_gid:   gid_t,
}

impl DavReadDir for SuidFsReadDir {}

impl Iterator for SuidFsReadDir {
    type Item = Box<DavDirEntry>;

    fn next(&mut self) -> Option<Box<DavDirEntry>> {
        match self.iterator.next() {
            None => return None,
            Some(entry) => Some(Box::new(SuidFsDirEntry{
                entry:  entry,
                user_uid:   self.user_uid,
                user_gid:   self.user_gid,
                base_uid:   self.base_uid,
                base_gid:   self.base_gid,
            }))
        }
    }
}

#[derive(Debug)]
struct SuidFsDirEntry {
    entry:  Box<DavDirEntry>,
    user_uid:   uid_t,
    user_gid:   gid_t,
    base_uid:   uid_t,
    base_gid:   gid_t,
}

impl SuidFsDirEntry {
    fn switch_uid(&self) -> FsResult<UidSwitcher> {
        UidSwitcher::new(self.user_uid, self.user_gid, self.base_uid, self.base_gid)
    }
}

impl DavDirEntry for SuidFsDirEntry {
    fn metadata(&self) -> FsResult<Box<DavMetaData>> {
        let _guard = self.switch_uid()?;
        self.entry.metadata()
    }

    fn name(&self) -> Vec<u8> {
        self.entry.name()
    }

    fn is_dir(&self) -> FsResult<bool> {
        let _guard = self.switch_uid()?;
        self.entry.is_dir()
    }
    fn is_file(&self) -> FsResult<bool> {
        let _guard = self.switch_uid()?;
        self.entry.is_file()
    }
    fn is_symlink(&self) -> FsResult<bool> {
        let _guard = self.switch_uid()?;
        self.entry.is_symlink()
    }
}

