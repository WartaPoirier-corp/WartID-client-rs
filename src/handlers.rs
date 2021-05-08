use std::collections::HashSet;

/// Route to initiate the authentication protocol
#[derive(Clone)]
pub struct Login {
    /// A path to redirect to once the flow reaches its end
    pub(crate) redirect_to: Option<String>,

    pub(crate) requested_scopes: HashSet<&'static str>,
}

impl Login {
    /// Constructs the most basic scopes request
    pub fn basic() -> Self {
        let mut scopes = HashSet::new();
        scopes.insert("basic");
        Self {
            redirect_to: None,
            requested_scopes: scopes,
        }
    }

    /// Adds email requirement to the scopes
    pub fn with_email(mut self) -> Self {
        self.requested_scopes.insert("email");
        self
    }

    /// Add or replaces the [redirection URL][Login::redirect_to] of the flow
    pub fn with_redirection(mut self, url: String) -> Self {
        self.redirect_to = Some(url);
        self
    }
}

/// OAuth2 callback route
#[derive(Copy, Clone)]
pub struct Callback;

/// Logout route
///
/// Once logged out, redirects the user to [R][R] if some, or else "/"
#[derive(Clone)]
pub struct Logout(pub Option<&'static str>);
