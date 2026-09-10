use serde_json::json;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use crate::{ClientSettings, SecretValue};

pub(crate) const LOGIN_PATH: &str = "/api/v1/auth/universal-auth/login";
pub(crate) const CA_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDMTCCAhmgAwIBAgIULV/ySWDTP/ej5wMvPTo0d1wqDlswDQYJKoZIhvcNAQEL\n\
BQAwIDEeMBwGA1UEAwwVbWNwLWluZmlzaWNhbC10ZXN0LWNhMB4XDTI2MDcxOTIz\n\
MzkwM1oXDTM2MDcxNjIzMzkwM1owIDEeMBwGA1UEAwwVbWNwLWluZmlzaWNhbC10\n\
ZXN0LWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjvSCDLJS/+vd\n\
hr7Yzltk+Ca3HkzaGg8Z19d7NwXC7D4w+ESWSA9XuxbaHz/EzXAwVSDonNSHprDm\n\
bNbkrGrLFFg5OSrhR3hpL0vHSLBdIWwwQ5qDf/CpTR12FqAlvGou9CLajnMbOfdM\n\
wNbqafgMJdpbqssQKHYaYm8BRN8WwMgJL8g4YZk7NIo/mq00cTBQUde1OIdorGCU\n\
Rq2c5JxgmzESaYvvAcOZ6/b1SJTp3ye3OvMh27yToUIG8eImdPvYIS3lFWM5zKxm\n\
yUqNa70pCNP3N6DdDKIZe0CLrxHOCugmg2zGHoWQTAjhKSm6OHrjN9uZTj6BrbhT\n\
PjvDtTJRwQIDAQABo2MwYTAdBgNVHQ4EFgQUHLC8AdmuxRgJy9TQCp3Sb5Zj9jcw\n\
HwYDVR0jBBgwFoAUHLC8AdmuxRgJy9TQCp3Sb5Zj9jcwDwYDVR0TAQH/BAUwAwEB\n\
/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBADAJP8doXv9an5W6\n\
Pgh03FFUMIs3Js0Z78QViddmBVHcvZDPYMPhZ37vckJr5M4M3lxr7FuUbR8UuzAE\n\
MeN0Ugl5OCzcm37ji54cDvfokN6kmgqamudW0OR/FD0KmsPoHOzhXDug1cCbUmkM\n\
PcTDFGyarvtDGziazYqfVCC91tGgmyYXA183UYmTMrsehjXGknbrd7W3VeXdD5Fl\n\
yD5VsnMrGIl08ZZkUFHb/TzTB0hHFxkPAO5YyEz9hjie1UINH3k4gLlLhTpZpJnQ\n\
37wZeDARTMv79TP2TzA3kWxuDFY7J3p36Lig2/GcMNJPOss99UNqL8eONLAFwdrc\n\
0oCYFjM=\n\
-----END CERTIFICATE-----";

pub(crate) fn settings(server: &MockServer) -> ClientSettings {
    ClientSettings::new(
        Url::parse(&server.uri()).expect("mock server URI must be valid"),
        "machine-client".into(),
        SecretValue::new("client-secret-canary"),
    )
}

pub(crate) fn login_response(token: &str, expires_in: u64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "accessToken": token,
        "expiresIn": expires_in,
        "accessTokenMaxTTL": expires_in * 2,
        "tokenType": "Bearer"
    }))
}

pub(crate) async fn mount_login(server: &MockServer, token: &str) {
    Mock::given(method("POST"))
        .and(path(LOGIN_PATH))
        .respond_with(login_response(token, 60))
        .mount(server)
        .await;
}
