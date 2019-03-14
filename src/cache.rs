use std::borrow::Borrow;
use std::cmp::Eq;
use std::collections::vec_deque::VecDeque;
use std::collections::HashMap;
use std::hash::Hash;
use std::option::Option;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[allow(dead_code)]
pub struct Cache<K, V> {
    intern: Mutex<Intern<K, V>>,
}

struct Intern<K, V> {
    maxsize: usize,
    maxage:  Duration,
    map:     HashMap<K, Arc<V>>,
    fifo:    VecDeque<(Instant, K)>,
}

impl<K: Hash + Eq + Clone, V> Cache<K, V> {
    pub fn new() -> Cache<K, V> {
        let i = Intern {
            maxsize: 0,
            maxage:  Duration::new(0, 0),
            map:     HashMap::new(),
            fifo:    VecDeque::new(),
        };
        Cache {
            intern: Mutex::new(i),
        }
    }

    #[allow(dead_code)]
    pub fn maxsize(self, maxsize: usize) -> Self {
        self.intern.lock().unwrap().maxsize = maxsize;
        self
    }

    #[allow(dead_code)]
    pub fn maxage(self, maxage: Duration) -> Self {
        self.intern.lock().unwrap().maxage = maxage;
        self
    }

    fn expire(&self, m: &mut Intern<K, V>) {
        let mut n = m.fifo.len();
        if m.maxsize > 0 && n >= m.maxsize {
            n = m.maxsize;
        }
        if m.maxage.as_secs() > 0 || m.maxage.subsec_nanos() > 0 {
            let now = Instant::now();
            while n > 0 {
                let &(t, _) = m.fifo.get(n - 1).unwrap();
                if now.duration_since(t) <= m.maxage {
                    break;
                }
                n -= 1;
            }
        }
        for x in n..m.fifo.len() {
            let &(_, ref key) = m.fifo.get(x).unwrap();
            m.map.remove(&key);
        }
        m.fifo.truncate(n);
    }

    pub fn insert(&self, key: K, val: V) -> Arc<V> {
        let mut m = self.intern.lock().unwrap();
        self.expire(&mut *m);
        let av = Arc::new(val);
        let ac = av.clone();
        m.map.insert(key.clone(), av);
        m.fifo.push_front((Instant::now(), key));
        ac
    }

    // see https://doc.rust-lang.org/book/first-edition/borrow-and-asref.html
    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<Arc<V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        let mut m = self.intern.lock().unwrap();
        self.expire(&mut *m);
        if let Some(v) = m.map.get(key) {
            return Some(v.clone());
        }
        None
    }
}
