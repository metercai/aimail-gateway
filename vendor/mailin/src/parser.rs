use nom::branch::alt;
use nom::bytes::complete::{is_not, tag, tag_no_case, take_while1};
use nom::character::is_alphanumeric;
use nom::combinator::{map, map_res, opt, value};
use nom::sequence::{pair, preceded, terminated};
use nom::IResult;

use crate::response::*;
use crate::smtp::{Cmd, Credentials};
use std::str;

//----- Parser -----------------------------------------------------------------

// Parse a line from the client
pub fn parse(line: &[u8]) -> Result<Cmd, Response> {
    command(line).map(|r| r.1).map_err(|e| match e {
        nom::Err::Incomplete(_) => MISSING_PARAMETER,
        nom::Err::Error(_) => SYNTAX_ERROR,
        nom::Err::Failure(_) => SYNTAX_ERROR,
    })
}

// Parse an authentication response from the client
pub fn parse_auth_response(line: &[u8]) -> Result<&[u8], Response> {
    auth_response(line).map(|r| r.1).map_err(|_| SYNTAX_ERROR)
}

fn command(buf: &[u8]) -> IResult<&[u8], Cmd> {
    terminated(
        alt((
            helo, ehlo, mail, rcpt, data, rset, quit, vrfy, noop, starttls, auth,
        )),
        tag(b"\r\n"),
    )(buf)
}

fn hello_domain(buf: &[u8]) -> IResult<&[u8], &str> {
    map_res(is_not(b" \t\r\n" as &[u8]), str::from_utf8)(buf)
}

fn helo(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parse_domain = preceded(cmd(b"helo"), hello_domain);
    map(parse_domain, |domain| Cmd::Helo { domain })(buf)
}

fn ehlo(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parse_domain = preceded(cmd(b"ehlo"), hello_domain);
    map(parse_domain, |domain| Cmd::Ehlo { domain })(buf)
}

fn mail_path(buf: &[u8]) -> IResult<&[u8], &str> {
    // RFC 5321 §4.1.1.2: MAIL FROM:<> is valid (null reverse-path for NDR/bounce).
    // mailin's is_not() rejects the closing `>` as an excluded char, so check
    // explicitly for an empty path first.
    if buf.first() == Some(&b'>') {
        return Ok((buf, ""));
    }
    map_res(is_not(b" <>\t\r\n" as &[u8]), str::from_utf8)(buf)
}

fn take_all(buf: &[u8]) -> IResult<&[u8], &str> {
    map_res(is_not(b"\r\n" as &[u8]), str::from_utf8)(buf)
}

fn mail_params(buf: &[u8]) -> IResult<&[u8], bool> {
    let mut remaining = buf;
    let mut is8bit = false;
    loop {
        // BODY=8BITMIME / BODY=7BIT
        if let Ok((rest, val)) = body_eq_8bit(remaining) {
            is8bit = val;
            remaining = rest;
            continue;
        }
        // Skip any other SMTP parameter (SIZE, AUTH, ENVID, etc.)
        if let Ok((rest, _)) = skip_one_esmtp_param(remaining) {
            remaining = rest;
            continue;
        }
        break;
    }
    Ok((remaining, is8bit))
}

fn body_eq_8bit(buf: &[u8]) -> IResult<&[u8], bool> {
    let preamble = pair(space, tag_no_case(b"body="));
    let is8bit = alt((
        value(true, tag_no_case(b"8bitmime")),
        value(false, tag_no_case(b"7bit")),
    ));
    preceded(preamble, is8bit)(buf)
}

fn skip_one_esmtp_param(buf: &[u8]) -> IResult<&[u8], ()> {
    let (buf, _) = space(buf)?;
    let (buf, _) = take_while1(|b: u8| b != b' ' && b != b'\r' && b != b'\n')(buf)?;
    Ok((buf, ()))
}

fn skip_esmtp_params(buf: &[u8]) -> IResult<&[u8], ()> {
    let mut remaining = buf;
    while let Ok((rest, _)) = skip_one_esmtp_param(remaining) {
        remaining = rest;
    }
    Ok((remaining, ()))
}

fn mail(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let (buf, _) = cmd(b"mail")(buf)?;
    let (buf, _) = tag_no_case(b"from:")(buf)?;
    let (buf, _) = opt(space)(buf)?; // RFC 5321 allows SP before <Reverse-path>
    let (buf, _) = tag(b"<")(buf)?;
    let (buf, reverse_path) = mail_path(buf)?;
    let (buf, _) = tag(b">")(buf)?;
    let (buf, is8bit) = mail_params(buf)?;
    Ok((buf, Cmd::Mail { reverse_path, is8bit }))
}

fn rcpt(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let (buf, _) = cmd(b"rcpt")(buf)?;
    let (buf, _) = tag_no_case(b"to:")(buf)?;
    let (buf, _) = opt(space)(buf)?; // RFC 5321 allows SP before <Forward-path>
    let (buf, _) = tag(b"<")(buf)?;
    let (buf, forward_path) = mail_path(buf)?;
    let (buf, _) = tag(b">")(buf)?;
    let (buf, _) = skip_esmtp_params(buf)?;
    Ok((buf, Cmd::Rcpt { forward_path }))
}

fn data(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Data, tag_no_case(b"data"))(buf)
}

fn rset(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Rset, tag_no_case(b"rset"))(buf)
}

fn quit(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Quit, tag_no_case(b"quit"))(buf)
}

fn vrfy(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let preamble = preceded(cmd(b"vrfy"), take_all);
    value(Cmd::Vrfy, preamble)(buf)
}

fn noop(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::Noop, tag_no_case(b"noop"))(buf)
}

fn starttls(buf: &[u8]) -> IResult<&[u8], Cmd> {
    value(Cmd::StartTls, tag_no_case(b"starttls"))(buf)
}

fn is_base64(chr: u8) -> bool {
    is_alphanumeric(chr) || (chr == b'+') || (chr == b'/' || chr == b'=')
}

fn auth_initial(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(space, take_while1(is_base64))(buf)
}

fn auth_response(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    terminated(take_while1(is_base64), tag("\r\n"))(buf)
}

fn empty(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    Ok((buf, b"" as &[u8]))
}

fn auth_plain(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parser = preceded(tag_no_case(b"plain"), alt((auth_initial, empty)));
    map(parser, sasl_plain_cmd)(buf)
}

fn auth_login(buf: &[u8]) -> IResult<&[u8], Cmd> {
    let parser = preceded(tag_no_case(b"login"), alt((auth_initial, empty)));
    map(parser, sasl_login_cmd)(buf)
}

fn auth(buf: &[u8]) -> IResult<&[u8], Cmd> {
    preceded(cmd(b"auth"), alt((auth_plain, auth_login)))(buf)
}

//---- Helper functions ---------------------------------------------------------

// Return a parser to match the given command
fn cmd(cmd_tag: &[u8]) -> impl Fn(&[u8]) -> IResult<&[u8], (&[u8], &[u8])> + '_ {
    move |buf: &[u8]| pair(tag_no_case(cmd_tag), space)(buf)
}

// Match one or more spaces
fn space(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|b| b == b' ')(buf)
}

fn sasl_plain_cmd(param: &[u8]) -> Cmd {
    if param.is_empty() {
        Cmd::AuthPlainEmpty
    } else {
        let creds = decode_sasl_plain(param);
        Cmd::AuthPlain {
            authorization_id: creds.authorization_id,
            authentication_id: creds.authentication_id,
            password: creds.password,
        }
    }
}

fn sasl_login_cmd(param: &[u8]) -> Cmd {
    if param.is_empty() {
        Cmd::AuthLoginEmpty
    } else {
        Cmd::AuthLogin {
            username: decode_sasl_login(param),
        }
    }
}

// Decodes the base64 encoded plain authentication parameter
pub(crate) fn decode_sasl_plain(param: &[u8]) -> Credentials {
    let decoded = base64::decode(param);
    if let Ok(bytes) = decoded {
        let mut fields = bytes.split(|b| b == &0u8);
        let authorization_id = next_string(&mut fields);
        let authentication_id = next_string(&mut fields);
        let password = next_string(&mut fields);
        Credentials {
            authorization_id,
            authentication_id,
            password,
        }
    } else {
        Credentials {
            authorization_id: String::default(),
            authentication_id: String::default(),
            password: String::default(),
        }
    }
}

// Decodes base64 encoded login authentication parameters (in login auth, username and password are
// sent in separate lines)
pub(crate) fn decode_sasl_login(param: &[u8]) -> String {
    let decoded = base64::decode(param).unwrap_or_default();
    String::from_utf8(decoded).unwrap_or_default()
}

fn next_string(it: &mut dyn Iterator<Item = &[u8]>) -> String {
    it.next()
        .map(|s| str::from_utf8(s).unwrap_or_default())
        .unwrap_or_default()
        .to_owned()
}

//---- Tests --------------------------------------------------------------------

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn mail_from_with_size() {
        // QQ mail server sends MAIL FROM with SIZE parameter
        let res = parse(b"MAIL FROM:<925457@qq.com> SIZE=12345\r\n");
        match res {
            Ok(Cmd::Mail { reverse_path, .. }) => {
                assert_eq!(reverse_path, "925457@qq.com");
            }
            _ => panic!("MAIL FROM with SIZE param incorrectly parsed"),
        };
    }

    #[test]
    fn mail_from_with_body_8bitmime() {
        let res = parse(b"MAIL FROM:<test@example.com> BODY=8BITMIME\r\n");
        match res {
            Ok(Cmd::Mail { reverse_path, .. }) => {
                assert_eq!(reverse_path, "test@example.com");
            }
            _ => panic!("MAIL FROM with BODY=8BITMIME incorrectly parsed"),
        };
    }

    #[test]
    fn mail_from_with_body_7bit() {
        let res = parse(b"MAIL FROM:<test@example.com> BODY=7BIT\r\n");
        match res {
            Ok(Cmd::Mail { reverse_path, .. }) => {
                assert_eq!(reverse_path, "test@example.com");
            }
            _ => panic!("MAIL FROM with BODY=7BIT incorrectly parsed"),
        };
    }

    #[test]
    fn mail_from_empty_bounce() {
        let res = parse(b"MAIL FROM:<>\r\n");
        match res {
            Ok(Cmd::Mail { reverse_path, .. }) => {
                assert_eq!(reverse_path, "");
            }
            _ => panic!("MAIL FROM:<> (bounce) incorrectly parsed"),
        };
    }

    #[test]
    fn mail_from_multiple_params() {
        // Some servers send multiple ESMTP parameters
        let res = parse(b"MAIL FROM:<user@domain.com> SIZE=9999 BODY=8BITMIME\r\n");
        match res {
            Ok(Cmd::Mail { reverse_path, .. }) => {
                assert_eq!(reverse_path, "user@domain.com");
            }
            _ => panic!("MAIL FROM with multiple params incorrectly parsed"),
        };
    }

    #[test]
    fn rcpt_to_with_notify() {
        // RCPT TO with DSN parameters (RFC 3461)
        let res = parse(b"RCPT TO:<tow@amail.token.tm> NOTIFY=SUCCESS,FAILURE\r\n");
        match res {
            Ok(Cmd::Rcpt { forward_path }) => {
                assert_eq!(forward_path, "tow@amail.token.tm");
            }
            _ => panic!("RCPT TO with NOTIFY param incorrectly parsed"),
        };
    }

    #[test]
    fn auth_initial_plain() {
        let res = parse(b"auth plain dGVzdAB0ZXN0ADEyMzQ=\r\n");
        match res {
            Ok(Cmd::AuthPlain {
                authorization_id,
                authentication_id,
                password,
            }) => {
                assert_eq!(authorization_id, "test");
                assert_eq!(authentication_id, "test");
                assert_eq!(password, "1234");
            }
            _ => panic!("Auth plain with initial response incorrectly parsed"),
        };
    }

    #[test]
    fn auth_initial_login() {
        let res = parse(b"auth login ZHVtbXk=\r\n");
        match res {
            Ok(Cmd::AuthLogin { username }) => {
                assert_eq!(username, "dummy");
            }
            _ => panic!("Auth login with initial response incorrectly parsed"),
        };
    }

    #[test]
    fn auth_empty_plain() {
        let res = parse(b"auth plain\r\n");
        match res {
            Ok(Cmd::AuthPlainEmpty) => {}
            _ => panic!("Auth plain without initial response incorrectly parsed"),
        };
    }

    #[test]
    fn auth_empty_login() {
        let res = parse(b"auth login\r\n");
        match res {
            Ok(Cmd::AuthLoginEmpty) => {}
            _ => panic!("Auth login without initial response incorrectly parsed"),
        };
    }
}
