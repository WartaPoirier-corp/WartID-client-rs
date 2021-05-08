#[cfg(not(any(feature = "rocket")))]
compile_error!("No feature selected, wartid-client is useless");

#[cfg(feature = "rocket")]
#[macro_use]
extern crate rocket as rocket_crate;

mod api;
pub mod handlers;
#[cfg(feature = "rocket")]
pub mod rocket;

trait HasReferer<'a> {
    fn referer(&'a self) -> &'a str;
}

pub struct WIDContextUrls {
    /// Login URL (local)
    pub login: String,

    /// Callback URL (local)
    pub callback: String,
}

impl WIDContextUrls {
    /// Assumes the login and callback routes are respectively `/oauth2/wartid/login` and
    /// `/oauth2/wartid/callback`.
    ///
    /// The base URL is given without a trailing slash
    pub fn from_base_url(base: &str) -> Self {
        debug_assert!(
            base.chars().rev().next() != Some('/'),
            "the base url shouldn't end with a slash",
        );

        Self {
            login: format!("{}/oauth2/wartid/login", base),
            callback: format!("{}/oauth2/wartid/callback", base),
        }
    }
}

/// User app / client credentials
///
/// The [Default][Default] implementation loads them from the `WARTID_CLIENT_ID` and
/// `WARTID_CLIENT_SECRET` environment variables, panics if they're not set.
pub struct WIDContextCredentials {
    pub client_id: String,
    pub(crate) client_secret: String,
}

impl WIDContextCredentials {
    pub const fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }
}

impl Default for WIDContextCredentials {
    fn default() -> Self {
        use std::env::var;

        Self {
            client_id: var("WARTID_CLIENT_ID").expect("no WARTID_CLIENT_ID set"),
            client_secret: var("WARTID_CLIENT_SECRET").expect("no WARTID_CLIENT_SECRET set"),
        }
    }
}

pub struct WIDContext {
    pub urls: WIDContextUrls,
    pub credentials: WIDContextCredentials,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct WartIDSession {
    pub id: uuid::Uuid,
    pub name: String,
    pub email: Option<String>,
    pub scopes: String,
}

#[derive(Copy, Clone, Debug)]
pub enum WartIDSessionError {
    MissingAuthorization,
    MissingRefresh,
    MissingUserinfo,
    SessionDecoding,
    Refreshing,
}

impl WartIDSessionError {
    /// Returns `true` if this error can be considered as the user being logged out
    ///
    /// This effectively returns `true` when one of the session-related cookies are missing
    pub fn is_logged_out(self) -> bool {
        match self {
            Self::MissingAuthorization | Self::MissingRefresh | Self::MissingUserinfo => true,
            Self::SessionDecoding | Self::Refreshing => false,
        }
    }
}

/// Convenient type that wraps an optional [WartIDSession][WartIDSession] that can be converted to a
/// `Result<WartIDSession, R>` where R is a type that acts as a redirection to the login page,
/// depending on your web framework.
///
/// # Example (Rocket)
///
/// ```
/// use rocket::response::Redirect;
/// use wartid_client::WartIDSessionOrRedirect;
///
/// #[get("/profile")]
/// fn profile(session: WartIDSessionOrRedirect) -> Result<String, Redirect> {
///     // If no session is active, a `Redirect` to the login page is thrown
///     let session = session.rocket()?;
///
///     Ok(format!("Your name id: {}", &session.name))
/// }
/// ```
pub struct WartIDSessionOrRedirect<'a>(Option<&'a WartIDSession>);
