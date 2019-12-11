//!
//! Simple and stupid HTTP router.
//!
use regex::bytes::{Match, Regex, RegexSet};
use std::default::Default;
use std::fmt::Debug;
use webdav_handler::{DavMethod, DavMethodSet};

// helper.
fn is_param_name(s: &str) -> bool {
    for c in s.chars() {
        if !((c >= 'a' && c <= 'z') || c == '_') {
            return false;
        }
    }
    s.len() > 0
}

// internal representation of a route.
#[derive(Debug)]
struct Route<T: Debug> {
    regex:   Regex,
    methods: Option<DavMethodSet>,
    data:    T,
}

/// A matched route.
#[derive(Debug)]
pub struct MatchedRoute<'t, 'p, T: Debug> {
    pub methods: Option<DavMethodSet>,
    pub params:  Vec<Option<Param<'p>>>,
    pub data:    &'t T,
}

/// A parameter on a matched route.
pub struct Param<'p>(Match<'p>);

impl Debug for Param<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Param")
            .field("start", &self.0.start())
            .field("end", &self.0.end())
            .field("as_str", &std::str::from_utf8(self.0.as_bytes()).ok())
            .finish()
    }
}

impl<'p> Param<'p> {
    /// Returns the starting byte offset of the match in the path.
    #[inline]
    pub fn start(&self) -> usize {
        self.0.start()
    }

    /// Returns the ending byte offset of the match in the path.
    #[inline]
    pub fn end(&self) -> usize {
        self.0.end()
    }

    /// Returns the matched part of the path.
    #[inline]
    pub fn as_bytes(&self) -> &'p [u8] {
        self.0.as_bytes()
    }

    /// Returns the matched part of the path as a &str, if it is valid utf-8.
    #[inline]
    pub fn as_str(&self) -> Option<&'p str> {
        std::str::from_utf8(self.0.as_bytes()).ok()
    }
}

pub struct Builder<T: Debug> {
    routes: Vec<Route<T>>,
}

impl<T: Debug> Builder<T> {
    /// Add a route.
    ///
    /// Routes are matched in the order they were added.
    ///
    /// If a route starts with '^', it's assumed that it is a regular
    /// expression. Parameters are included as "named capture group".
    /// Otherwise, it's just the normal :pathelem and *splat params.
    ///
    pub fn add(
        &mut self,
        route: impl AsRef<str>,
        methods: Option<DavMethodSet>,
        data: T,
    ) -> Result<&mut Self, regex::Error>
    {
        let route = route.as_ref();
        // Might be a regexp
        if route.starts_with("^") {
            return self.add_re(route, methods, data);
        }
        // Ignore it if it does not start with /
        if !route.starts_with("/") {
            return Ok(self);
        }

        // Translate route expression into regexp.
        let mut words = Vec::new();
        let slash_end = route.len() > 1 && route.ends_with("/");

        // split in path elements
        for w in route.split("/").filter(|s| !s.is_empty()) {
            // translate :param and *param to named capture groups.
            let param = &w[1..];
            let n = if w.starts_with(":") && is_param_name(param) {
                format!(r"(?P<{}>[^/]*)", param)
            } else if w.starts_with("*") && is_param_name(param) {
                format!(r"(?P<{}>.*)", param)
            } else {
                regex::escape(w)
            };
            words.push(n);
        }

        // finalize regex.
        let mut r = "^/".to_string() + &words.join("/");
        if slash_end {
            r.push('/');
        }
        r.push('$');

        self.add_re(&r, methods, data)
    }

    // add route as regular expression.
    fn add_re(&mut self, s: &str, methods: Option<DavMethodSet>, data: T) -> Result<&mut Self, regex::Error> {
        // Set flags: enable ". matches everything", disable strict unicode.
        // We known 's' starts with "^", add it after that.
        let s2 = format!("^(?s){}", &s[1..]);
        let regex = Regex::new(&s2)?;
        self.routes.push(Route { regex, methods, data });
        Ok(self)
    }

    /// Combine all the routes and compile them into an internal RegexSet.
    pub fn build(self) -> Router<T> {
        let set = RegexSet::new(self.routes.iter().map(|r| r.regex.as_str())).unwrap();
        Router {
            routes: self.routes,
            set,
        }
    }
}

/// Dead simple HTTP router.
#[derive(Debug)]
pub struct Router<T: Debug> {
    set:    RegexSet,
    routes: Vec<Route<T>>,
}

impl<T: Debug> Default for Router<T> {
    fn default() -> Router<T> {
        Router {
            set:    RegexSet::new(&[] as &[&str]).unwrap(),
            routes: Vec::new(),
        }
    }
}

impl<T: Debug> Router<T> {
    /// Return a builder.
    pub fn builder() -> Builder<T> {
        Builder { routes: Vec::new() }
    }

    /// See if the path matches a route in the set.
    ///
    /// The names of the parameters you want to be returned need to be passed in as an array.
    pub fn matches<'a>(
        &self,
        path: &'a [u8],
        method: DavMethod,
        param_names: &[&str],
    ) -> Vec<MatchedRoute<'_, 'a, T>>
    {
        let mut matched = Vec::new();
        for idx in self.set.matches(path) {
            let route = &self.routes[idx];
            if route.methods.map(|m| m.contains(method)).unwrap_or(true) {
                let mut params = Vec::new();
                if let Some(caps) = route.regex.captures(path) {
                    for name in param_names {
                        params.push(caps.name(name).map(|p| Param(p)));
                    }
                } else {
                    for _ in param_names {
                        params.push(None);
                    }
                }
                matched.push(MatchedRoute {
                    methods: route.methods,
                    params,
                    data: &route.data,
                });
            }
        }
        matched
    }
}
