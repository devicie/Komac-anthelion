//! Expansion of [Inno Setup constants] whose values are known when an installer is analysed.
//!
//! Only custom message constants (`{cm:Name}` and `{cm:Name,Argument,...}`) can be resolved from
//! the installer itself. Every other constant, such as `{app}`, `{code:...}`, `{reg:...}` or
//! `{param:...}`, depends on the machine or on code run during setup, so a value containing one
//! can't be resolved.
//!
//! [Inno Setup constants]: https://jrsoftware.org/ishelp/index.php?topic=consts

use inno::InnoInner;

/// The prefix of a custom message constant.
const CUSTOM_MESSAGE: &str = "cm:";

/// The maximum depth of constants nested within the parameters of other constants.
const MAX_DEPTH: u8 = 8;

/// Expands the constants in `value` using the custom messages of `inno`.
///
/// Returns [`None`] if `value` contains a constant that can't be resolved, or a malformed one.
pub fn expand(inno: &InnoInner, value: &str) -> Option<String> {
    expand_with(value, |name| custom_message(inno, name))
}

/// Returns the value of the custom message called `name`.
///
/// Inno uses the message for the selected language, falling back to a message shared by all
/// languages. As the selected language isn't known, the message for the primary language is
/// preferred, then a message shared by all languages, then a message for any language.
fn custom_message<'inno>(inno: &'inno InnoInner, name: &str) -> Option<&'inno str> {
    let messages = inno.message_entries().iter().filter(|message| {
        message
            .name()
            .is_some_and(|message_name| message_name.eq_ignore_ascii_case(name))
    });

    let mut shared = None;
    let mut other = None;
    for message in messages {
        match message.language_index() {
            0 => return message.value(),
            index if index < 0 => shared = shared.or(message.value()),
            _ => other = other.or(message.value()),
        }
    }

    shared.or(other)
}

/// Expands the constants in `value`, looking up custom messages with `lookup`.
fn expand_with<'a, F>(value: &str, lookup: F) -> Option<String>
where
    F: Fn(&str) -> Option<&'a str> + Copy,
{
    expand_at_depth(value, lookup, 0)
}

fn expand_at_depth<'a, F>(value: &str, lookup: F, depth: u8) -> Option<String>
where
    F: Fn(&str) -> Option<&'a str> + Copy,
{
    if depth > MAX_DEPTH {
        return None;
    }

    let mut expanded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('{') {
        expanded.push_str(&rest[..start]);
        rest = &rest[start + '{'.len_utf8()..];

        // Two opening braces are an escaped literal brace
        if let Some(after_escape) = rest.strip_prefix('{') {
            expanded.push('{');
            rest = after_escape;
            continue;
        }

        let end = constant_end(rest)?;
        expanded.push_str(&resolve(&rest[..end], lookup, depth)?);
        rest = &rest[end + '}'.len_utf8()..];
    }
    expanded.push_str(rest);

    Some(expanded)
}

/// Returns the index of the brace that closes the constant at the start of `value`, accounting for
/// nested constants.
fn constant_end(value: &str) -> Option<usize> {
    let mut depth = 0_usize;
    for (index, char) in value.char_indices() {
        match char {
            '{' => depth += 1,
            '}' if depth == 0 => return Some(index),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Resolves the body of a single constant, such as `cm:AppName`.
fn resolve<'a, F>(constant: &str, lookup: F, depth: u8) -> Option<String>
where
    F: Fn(&str) -> Option<&'a str> + Copy,
{
    let parameters = constant.strip_prefix(CUSTOM_MESSAGE)?;

    let mut parameters = split_parameters(parameters)
        .into_iter()
        .map(|parameter| expand_at_depth(parameter, lookup, depth + 1).map(|value| decode(&value)));

    let name = parameters.next()??;
    let arguments = parameters.collect::<Option<Vec<_>>>()?;

    Some(format_message(lookup(name.trim())?, &arguments))
}

/// Splits the parameters of a constant on the commas that aren't inside a nested constant.
fn split_parameters(parameters: &str) -> Vec<&str> {
    let mut split = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0;
    for (index, char) in parameters.char_indices() {
        match char {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                split.push(&parameters[start..index]);
                start = index + ','.len_utf8();
            }
            _ => {}
        }
    }
    split.push(&parameters[start..]);
    split
}

/// Decodes the `%xx` hexadecimal escapes that Inno allows in constant parameters, such as `%2c`
/// for a comma and `%7d` for a closing brace.
fn decode(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find('%') {
        decoded.push_str(&rest[..index]);
        let escape = &rest[index..];
        if let Some(char) = escape
            .get(1..3)
            .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            .filter(u8::is_ascii)
        {
            decoded.push(char::from(char));
            rest = &escape[3..];
        } else {
            decoded.push('%');
            rest = &escape[1..];
        }
    }
    decoded.push_str(rest);
    decoded
}

/// Formats a custom message, replacing `%1` to `%9` with the arguments and `%%` with `%`, as Inno's
/// `FmtMessage` does.
fn format_message(message: &str, arguments: &[String]) -> String {
    let mut formatted = String::with_capacity(message.len());
    let mut chars = message.chars().peekable();
    while let Some(char) = chars.next() {
        if char != '%' {
            formatted.push(char);
            continue;
        }

        match chars.peek().copied() {
            Some('%') => {
                chars.next();
                formatted.push('%');
            }
            Some(digit @ '1'..='9') => {
                chars.next();
                let index = digit as usize - '1' as usize;
                if let Some(argument) = arguments.get(index) {
                    formatted.push_str(argument);
                } else {
                    formatted.push('%');
                    formatted.push(digit);
                }
            }
            _ => formatted.push('%'),
        }
    }
    formatted
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::expand_with;

    fn lookup(name: &str) -> Option<&'static str> {
        match name.to_ascii_lowercase().as_str() {
            "appname" => Some("Example App"),
            "publisher" => Some("Example Corp"),
            "nameandversion" => Some("%1 version %2"),
            "percent" => Some("100%% %1"),
            _ => None,
        }
    }

    #[rstest]
    #[case("Example App", Some("Example App"))]
    #[case("{cm:AppName}", Some("Example App"))]
    #[case("{cm:appname}", Some("Example App"))]
    #[case("{cm:AppName} by {cm:Publisher}", Some("Example App by Example Corp"))]
    #[case(
        "{cm:NameAndVersion,{cm:AppName},1.2.3}",
        Some("Example App version 1.2.3")
    )]
    #[case("{cm:NameAndVersion,A%2cB,1%7d}", Some("A,B version 1}"))]
    #[case("{cm:Percent,done}", Some("100% done"))]
    #[case("{cm:NameAndVersion,App}", Some("App version %2"))]
    #[case(
        "{{00000000-0000-0000-0000-000000000000}",
        Some("{00000000-0000-0000-0000-000000000000}")
    )]
    #[case("{cm:Missing}", None)]
    #[case("{code:GetAppName}", None)]
    #[case("Copyright 2015-{code:GetCurrentYear} Example Corp", None)]
    #[case("{app}", None)]
    #[case("{cm:AppName", None)]
    fn expand(#[case] value: &str, #[case] expected: Option<&str>) {
        assert_eq!(expand_with(value, lookup).as_deref(), expected);
    }
}
