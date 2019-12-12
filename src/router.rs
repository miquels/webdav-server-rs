//!
//! Simple and stupid HTTP router.
//!
use std::default::Default;
use std::fmt::Debug;

use lazy_static::lazy_static;
use regex::bytes::{Match, Regex, RegexSet};
use webdav_handler::{DavMethod, DavMethodSet};

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
    /// expression. Parameters are included as "named capture groups".
    ///
    /// Otherwise, it's a route-expression, with just the normal :params
    /// and *splat param, and parts between parentheses are optional.
    ///
    /// Example:
    ///
    /// - /api/get/:id
    /// - /files/*path
    /// - /users(/)
    /// - /users(/*path)
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

        // First, replace special characters "()*" with unicode chars
        // from the private-use area, so that we can then regex-escape
        // the entire string.
        let re_route = route
            .chars()
            .map(|c| match c {
                '*' => '\u{e001}',
                '(' => '\u{e002}',
                ')' => '\u{e003}',
                '\u{e001}' => ' ',
                '\u{e002}' => ' ',
                '\u{e003}' => ' ',
                c => c,
            }).collect::<String>();
        let re_route = regex::escape(&re_route);

        // Translate route expression into regexp.
        // We do a simple transformation:
        //    :ident -> (?P<ident>[^/]*)
        //    *ident -> (?P<ident>.*)
        //    (text) -> (?:text|)
        lazy_static! {
            static ref COLON: Regex = Regex::new(":([a-zA-Z0-9]+)").unwrap();
            static ref SPLAT: Regex = Regex::new("\u{e001}([a-zA-Z0-9]+)").unwrap();
            static ref MAYBE: Regex = Regex::new("\u{e002}([^\u{e002}]*)\u{e003}").unwrap();
        };
        let mut re_route = re_route.into_bytes();
        re_route = COLON.replace_all(&re_route, &b"(?P<$1>[^/]*)"[..]).to_vec();
        re_route = SPLAT.replace_all(&re_route, &b"(?P<$1>.*)"[..]).to_vec();
        re_route = MAYBE.replace_all(&re_route, &b"($1)?"[..]).to_vec();

        // finalize regex.
        let re_route = "^".to_string() + &String::from_utf8(re_route).unwrap() + "$";

        self.add_re(&re_route, methods, data)
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
    pub fn build(&mut self) -> Router<T> {
        let set = RegexSet::new(self.routes.iter().map(|r| r.regex.as_str())).unwrap();
        Router {
            routes: std::mem::replace(&mut self.routes, Vec::new()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use webdav_handler::DavMethod;

    fn test_match(rtr: &Router<usize>, p: &[u8], user: &str, path: &str) {
        let x = rtr.matches(p, DavMethod::Get, &[ "user", "path" ]);
        assert!(x.len() > 0);
        let x = &x[0];
        if user != "" {
            assert!(x.params[0].as_ref().map(|b| b.as_bytes() == user.as_bytes()).unwrap_or(false));
        }
        if path != "" {
            assert!(x.params[1].as_ref().map(|b| b.as_bytes() == path.as_bytes()).unwrap_or(false));
        }
    }

    #[test]
    fn test_router() -> Result<(), Box<dyn std::error::Error>> {
        let rtr = Router::<usize>::builder()
            .add("/", None, 1)?
            .add("/users(/:user)", None, 2)?
            .add("/files/*path", None, 3)?
            .add("/files(/*path)", None, 4)?
            .build();

        test_match(&rtr, b"/", "", "");
        test_match(&rtr, b"/users", "", "");
        test_match(&rtr, b"/users/", "", "");
        test_match(&rtr, b"/users/mike", "mike", "");
        test_match(&rtr, b"/files/foo/bar", "", "foo/bar");
        test_match(&rtr, b"/files", "", "");
        Ok(())
    }
}
