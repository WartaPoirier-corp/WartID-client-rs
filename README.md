# WartID – Rust client

_A Rust client for the WPCorp's identity provider: WartID_

## Usage with Rocket

**note:** this library requires Rocket v0.5.+

```rust
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::response::Redirect;
use wartid_client::handlers;
use wartid_client::*;

#[get("/")]
fn index(user: WartIDSessionOrRedirect) -> Result<String, Redirect> {
    // Redirects to the login page if no-one is connected
    let user: WartIDSession = user.rocket()?;

    Ok(format!("Hello {}", &user.name))
}

#[get("/logout")]
fn logout() -> handlers::Logout {
    handlers::Logout(None)
}

#[launch]
fn rocket() -> _ {
    let client_state = wartid_client::WIDContext {
        urls: wartid_client::WIDContextUrls::from_base_url("https://wartaservice.site"),
        // Loads OAuth2 client credentials from environment variables
        credentials: Default::default(),
    };

    rocket::ignite()
        .manage(client_state)
        .mount("/", routes![index, logout])
        .mount("/oauth2/wartid", wartid_client::rocket::routes(true))
}
```

## TODO

  * [ ] Fix CSRF on the `/logout` handler
  * [ ] Fix the email scope
