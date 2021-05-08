use crate::{WIDContext, WartIDSession};
use chrono::{TimeZone, Utc};
use reqwest::Url;
use uuid::Uuid;

pub struct Client {
    url_token: Url,
    url_userinfo: Url,
    client: reqwest::Client,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            url_token: Url::parse("https://id.wp-corp.eu.org/oauth2/token").unwrap(),
            url_userinfo: Url::parse("https://id.wp-corp.eu.org/oauth2/userinfo").unwrap(),
            client: reqwest::Client::builder().build().unwrap(),
        }
    }
}

#[derive(serde::Serialize)]
pub struct TokenRequestData<'a> {
    grant_type: &'static str,
    code: Option<&'a str>,
    refresh_token: Option<&'a str>,
    redirect_uri: &'static str,
    scope: Option<&'a str>,

    client_id: &'a str,
    client_secret: &'a str,
}

#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    expires_in: u64,
    token_type: String,
    pub refresh_token: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct UserInfoResponse {
    sub: Uuid,
    name: String,
    email: Option<String>,
}

impl From<UserInfoResponse> for WartIDSession {
    fn from(info: UserInfoResponse) -> Self {
        Self {
            id: info.sub,
            name: info.name,
            email: info.email,
            scopes: "".into(), // TODO
        }
    }
}

pub enum Authorization<'a> {
    Clean {
        access_token: &'a str,
        refresh_token: &'a str,
    },
    /// Set when the tokens were refreshed. They should be written back to cookies before dropping,
    /// or the session will be invalid starting from the next request.
    Dirty {
        access_token: String,
        refresh_token: String,
    },
}

impl<'a> Authorization<'a> {
    pub fn new(access_token: &'a str, refresh_token: &'a str) -> Self {
        Self::Clean {
            access_token,
            refresh_token,
        }
    }
}

impl Authorization<'_> {
    fn access_token(&self) -> &str {
        match self {
            Self::Clean { access_token, .. } => *access_token,
            Self::Dirty { access_token, .. } => &*access_token,
        }
    }

    fn refresh_token(&self) -> &str {
        match self {
            Self::Clean { refresh_token, .. } => *refresh_token,
            Self::Dirty { refresh_token, .. } => &*refresh_token,
        }
    }

    pub fn expired(&self) -> bool {
        #[derive(serde::Deserialize)]
        struct PartialClaims {
            exp: u64,
        }

        match jsonwebtoken::dangerous_insecure_decode::<PartialClaims>(self.access_token()) {
            Ok(claims) => {
                let expiration = Utc.timestamp(claims.claims.exp as _, 0);

                expiration < Utc::now()
            }
            Err(err) => {
                log::error!("[Authorization::expired] {}", err);
                true
            }
        }
    }

    pub async fn try_refresh(
        &mut self,
        context: &WIDContext,
        client: &Client,
    ) -> Result<(), reqwest::Error> {
        if self.expired() {
            log::debug!(
                "[Authorization::try_refresh] refreshing {}",
                self.access_token()
            );

            let token = client
                .request_token_refresh(context, self.refresh_token())
                .await?;

            *self = Self::Dirty {
                access_token: token.access_token,
                refresh_token: token
                    .refresh_token
                    .unwrap_or_else(|| self.refresh_token().to_string()),
            };
        }

        Ok(())
    }

    async fn bearer(
        &mut self,
        context: &WIDContext,
        client: &Client,
    ) -> Result<&str, reqwest::Error> {
        self.try_refresh(context, client).await?;
        Ok(self.access_token())
    }
}

impl Client {
    pub async fn request_token(
        &self,
        context: &WIDContext,
        authorization_code: &str,
    ) -> Result<TokenResponse, reqwest::Error> {
        let data = TokenRequestData {
            grant_type: "authorization_code",
            code: Some(authorization_code),
            refresh_token: None,
            redirect_uri: "",
            scope: None,

            client_id: &context.credentials.client_id,
            client_secret: &context.credentials.client_secret,
        };

        let response = self
            .client
            .post(self.url_token.clone())
            .form(&data)
            .send()
            .await?;

        Ok(response.json().await?)
    }

    pub async fn request_token_refresh(
        &self,
        context: &WIDContext,
        refresh_token: &str,
    ) -> Result<TokenResponse, reqwest::Error> {
        let data = TokenRequestData {
            grant_type: "refresh_token",
            code: None,
            refresh_token: Some(refresh_token),
            redirect_uri: "",
            scope: None,

            client_id: &context.credentials.client_id,
            client_secret: &context.credentials.client_secret,
        };

        let response = self
            .client
            .post(self.url_token.clone())
            .form(&data)
            .send()
            .await?;

        Ok(response.json().await?)
    }

    pub async fn request_userinfo<'a>(
        &self,
        context: &WIDContext,
        authorization: &mut Authorization<'a>,
    ) -> Result<UserInfoResponse, reqwest::Error> {
        let response = self
            .client
            .get(self.url_userinfo.clone())
            .header(
                "Authorization",
                &format!("Bearer {}", authorization.bearer(context, self).await?),
            )
            .send()
            .await?;

        Ok(response.json().await?)
    }
}
