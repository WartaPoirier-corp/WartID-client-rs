#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::response::content::Html;
use rocket::response::Redirect;
use wartid_client::handlers;
use wartid_client::*;

#[get("/")]
fn home(user: Result<&WartIDSession, WartIDSessionError>) -> Html<String> {
    match user {
        Ok(user) => Html(format!(
            r#"Logged in as {} (@{} - {:?})<br/><a href="/logout">Log out</a>"#,
            user.name, user.id, user.email,
        )),
        Err(e) => Html(format!(
            r#"Disconnected ({:?})<br/><a href="/oauth2/wartid/login">Connect</a>"#,
            e,
        )),
    }
}

#[get("/admin")]
fn very_secret_panel(user: WartIDSessionOrRedirect) -> Result<String, Redirect> {
    let user = user.rocket()?;

    Ok(format!("Hello {}", &user.name))
}

#[get("/logout")]
fn logout() -> handlers::Logout {
    handlers::Logout(None)
}

#[launch]
fn rocket() -> _ {
    let client_state = wartid_client::WIDContext {
        urls: wartid_client::WIDContextUrls::from_base_url("https://edgar.bzh:8000"),
        credentials: Default::default(),
    };

    rocket::ignite()
        .manage(client_state)
        .mount("/", routes![home, very_secret_panel, logout])
        .mount("/oauth2/wartid", wartid_client::rocket::routes(true))
}
