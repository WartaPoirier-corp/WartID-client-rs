//! # Rocket support for the crate
//!
//! ## How to implement ?
//!
//! You have to choose:
//!   * The [login url][crate::WIDContextUrls::login]. This is where you redirect users who want to
//!     log in using WartID
//!   * The [callback url][crate::WIDContextUrls::callback]. This is where WartID will redirect the
//!     user's browser once they have approved logging into your site
//!
//! Checklist:
//!   * Have a secret cookie key set up (static to preserve sessions after restarts)
//!   * Have a `manage`d [State][crate::State] instance
//!   * Have a [login url][crate::WIDContextUrls::login] route that responds with a
//!     [handlers::Login][crate::handlers::Login]
//!   * Have a [callback url][crate::WIDContextUrls::callback] route that responds with a
//!     [handlers::Callback][crate::handlers::Callback]
//!
//! ## What will you be able to do ?
//!
//!   * Use request guards to obtain information about the current session
//!       * `WartIDSession` gives you a valid session or fails with `401 Unauthorized`
//!       * `Option<WartIDSession>` or `Result<WartIDSession, WartIDError>` doesn't fail if no one
//!         is authenticated
//!       * `WartIDSessionOrLogin` redirects the user to the login page if no WartIDSession is
//!         active, or contains a `WartIDSession`

use crate::api::{Authorization, Client};
use crate::handlers::*;
use crate::{WIDContext, WartIDSession, WartIDSessionError, WartIDSessionOrRedirect};
use rocket::handler::Handler;
use rocket::http::{Cookie, Method, SameSite, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::{Redirect, Responder};
use rocket::{Data, Request, Route};

pub fn routes(with_email: bool) -> Vec<Route> {
    let login = if with_email {
        Login::basic().with_email()
    } else {
        Login::basic()
    };

    vec![
        Route::new(Method::Get, "/login", login),
        Route::new(Method::Get, "/callback", Callback),
    ]
}

const STATE_LENGTH: usize = 20;

fn rand_state() -> String {
    use rand::{distributions::Alphanumeric, Rng};

    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(STATE_LENGTH)
        .map(char::from)
        .collect()
}

impl<'r> Responder<'r, 'static> for Login {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let cookies = request.cookies();
        let context: &WIDContext = request.rocket().state().expect("state isn't set");

        let mut state = rand_state();
        if let Some(red) = self.redirect_to {
            state.push_str(&red);
        };

        #[derive(serde::Serialize)]
        struct Authorize<'a> {
            response_type: &'a str,
            client_id: &'a str,
            redirect_uri: &'a str,
            scope: &'a str,
            state: &'a str,
            // nonce ?
        }

        let authorize = match serde_urlencoded::to_string(Authorize {
            response_type: "code",
            client_id: &context.credentials.client_id,
            redirect_uri: &context.urls.callback,
            scope: &self
                .requested_scopes
                .into_iter()
                .collect::<Vec<_>>()
                .join(" "),
            state: &state,
        }) {
            Ok(x) => x,
            Err(_) => return Status::InternalServerError.respond_to(request),
        };

        let redirect = format!("https://id.wp-corp.eu.org/oauth2/authorize?{}", authorize);

        cookies.add_private(
            Cookie::build("wartid_auth_state", state)
                .max_age(time::Duration::minutes(10))
                .same_site(SameSite::Lax)
                .finish(),
        );

        Redirect::temporary(redirect).respond_to(request)
    }
}

#[async_trait]
impl Handler for Login {
    async fn handle<'r, 's: 'r>(
        &'s self,
        request: &'r Request<'_>,
        _: Data,
    ) -> rocket::handler::Outcome<'r> {
        rocket::handler::Outcome::from(request, self.clone())
    }
}

#[derive(Debug, serde::Deserialize)]
struct CallbackParams<'a> {
    code: &'a str,
    state: &'a str,
}

#[rocket::async_trait]
impl Handler for Callback {
    async fn handle<'r, 's: 'r>(
        &'s self,
        request: &'r Request<'_>,
        _: Data,
    ) -> rocket::handler::Outcome<'r> {
        use rocket::handler::Outcome;

        let cookies = request.cookies();
        let context: &WIDContext = request.rocket().state().expect("state isn't set");
        let query: Option<&str> = request.uri().query().map(AsRef::as_ref);
        let params: CallbackParams =
            match serde_urlencoded::from_str(query.as_deref().unwrap_or_default()) {
                Ok(params) => params,
                Err(_err) => {
                    return Outcome::Failure(Status::BadRequest);
                }
            };

        // State verification
        if let Some(expected_state_cookie) = cookies.get_private("wartid_auth_state") {
            if expected_state_cookie.value() != params.state {
                return Outcome::Failure(Status::Unauthorized);
            }

            cookies.remove_private(Cookie::named("wartid_auth_state"));
        } else {
            return Outcome::Failure(Status::BadRequest);
        }

        let client = Client::default(); // TODO optimise
        let token_response = client.request_token(context, params.code).await;

        let token = match token_response {
            Ok(token) => token,
            Err(err) => {
                error!("Request error: {:?}", err);
                return Outcome::from(request, Status::InternalServerError);
            }
        };

        if let Some(refresh) = token.refresh_token {
            let mut authorization = Authorization::new(&token.access_token, &refresh);

            let userinfo = match client.request_userinfo(context, &mut authorization).await {
                Ok(userinfo) => userinfo,
                Err(err) => {
                    log::error!("[Callback::handle] {}", err);
                    return Outcome::Failure(Status::BadRequest);
                }
            };

            let session: WartIDSession = userinfo.into();

            cookies.add_private(
                Cookie::build("wartid_s", serde_json::to_string(&session).unwrap())
                    .same_site(SameSite::Lax)
                    .finish(),
            );

            cookies.add_private(
                Cookie::build("wartid_r", refresh)
                    .same_site(SameSite::Lax)
                    .finish(),
            );
        }

        cookies.add_private(
            Cookie::build("wartid_a", token.access_token)
                .same_site(SameSite::Lax)
                .finish(),
        );

        rocket::handler::Outcome::from(request, Redirect::temporary("/"))
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Logout {
    fn respond_to(self, request: &Request<'_>) -> rocket::response::Result<'o> {
        let cookies = request.cookies();

        cookies.remove_private(Cookie::named("wartid_a"));
        cookies.remove_private(Cookie::named("wartid_r"));
        cookies.remove_private(Cookie::named("wartid_data"));

        Redirect::to(self.0.unwrap_or("/")).respond_to(request)
    }
}

#[rocket::async_trait]
impl Handler for Logout {
    async fn handle<'r, 's: 'r>(
        &'s self,
        request: &'r Request<'_>,
        _: Data,
    ) -> rocket::handler::Outcome<'r> {
        rocket::handler::Outcome::from(request, self.clone())
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r WartIDSession {
    type Error = WartIDSessionError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let result = request
            .local_cache_async::<Result<WartIDSession, Self::Error>, _>(async {
                let cookies = request.cookies();
                let context: &WIDContext = request.rocket().state().expect("state isn't set");

                let c_a = cookies.get_private("wartid_a");
                let c_a_val = match &c_a {
                    Some(cookie) => cookie.value(),
                    None => return Err(WartIDSessionError::MissingAuthorization),
                };

                let c_r = cookies.get_private("wartid_r");
                let c_r_val = match &c_r {
                    Some(cookie) => cookie.value(),
                    None => return Err(WartIDSessionError::MissingRefresh),
                };

                let mut authorization = Authorization::new(c_a_val, c_r_val);
                if let Err(err) = authorization.try_refresh(context, &Client::default()).await {
                    log::error!("[WartIDSession::from_request] error refreshing: {}", err);
                    return Err(WartIDSessionError::Refreshing);
                }

                if let Authorization::Dirty {
                    access_token,
                    refresh_token,
                } = authorization
                {
                    cookies.add_private(
                        Cookie::build("wartid_r", refresh_token)
                            .same_site(SameSite::Lax)
                            .finish(),
                    );

                    cookies.add_private(
                        Cookie::build("wartid_a", access_token)
                            .same_site(SameSite::Lax)
                            .finish(),
                    );
                }

                let c_s = cookies.get_private("wartid_s");
                let c_s_val = match &c_s {
                    Some(cookie) => cookie.value(),
                    None => return Err(WartIDSessionError::MissingUserinfo),
                };

                let session = match serde_json::from_str::<WartIDSession>(c_s_val) {
                    Ok(x) => x,
                    Err(_) => return Err(WartIDSessionError::SessionDecoding),
                };

                Ok(session)
            })
            .await;

        match result {
            Ok(session) => Outcome::Success(session),
            Err(err) => Outcome::Failure((Status::Unauthorized, *err)),
        }
    }
}

impl<'a> WartIDSessionOrRedirect<'a> {
    pub fn rocket(self) -> Result<&'a WartIDSession, Redirect> {
        self.0.ok_or_else(|| Redirect::to("/oauth2/wartid/login"))
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for WartIDSessionOrRedirect<'r> {
    type Error = WartIDSessionError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let session: Outcome<&WartIDSession, WartIDSessionError> = request.guard().await;

        match session {
            Outcome::Success(s) => Outcome::Success(Self(Some(s))),
            Outcome::Forward(()) => Outcome::Forward(()),
            Outcome::Failure((_, err)) if err.is_logged_out() => Outcome::Success(Self(None)),
            Outcome::Failure(f) => Outcome::Failure(f),
        }
    }
}
