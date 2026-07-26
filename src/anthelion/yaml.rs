use std::collections::HashMap;

use color_eyre::eyre::Report;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde_json::{Map, Value, map::Entry};
use serde_saphyr::{
    DuplicateKeyPolicy,
    granit_parser::{ErrorKind, Event, Marker, Parser, ScalarStyle, ScanError, Span, StrInput},
};

use super::error::{AnthelionError, ErrorCode};

const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 1_000_000;

type ParseResult<T> = std::result::Result<T, ParseError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceRange {
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct ParseError {
    message: String,
    code: &'static str,
    range: Option<SourceRange>,
}

impl ParseError {
    fn new(message: impl Into<String>, code: &'static str, range: SourceRange) -> Self {
        Self {
            message: message.into(),
            code,
            range: Some(range),
        }
    }

    fn at_span(input: &str, message: impl Into<String>, code: &'static str, span: &Span) -> Self {
        Self::new(message, code, SourceRange::from_span(input, span))
    }

    fn at_end(input: &str, message: impl Into<String>) -> Self {
        Self::new(
            message,
            "UNEXPECTED_TOKEN",
            SourceRange {
                start: input.len(),
                end: input.len(),
            },
        )
    }

    fn from_scan_error(input: &str, error: ScanError) -> Self {
        let code = match error.kind() {
            ErrorKind::UnknownAnchor => "BAD_ALIAS",
            ErrorKind::MultipleDocumentsUnsupported => "MULTIPLE_DOCS",
            ErrorKind::TooManyComments | ErrorKind::AnchorCountOverflow => "RESOURCE_EXHAUSTION",
            _ => "UNEXPECTED_TOKEN",
        };
        let range = SourceRange::at_marker(input, error.marker());

        Self::new(error.to_string(), code, range)
    }

    fn from_serde_error(input: &str, error: serde_saphyr::Error) -> Self {
        let code = match error.without_snippet() {
            serde_saphyr::Error::DuplicateMappingKey { .. } => "DUPLICATE_KEY",
            serde_saphyr::Error::MultipleDocuments { .. } => "MULTIPLE_DOCS",
            serde_saphyr::Error::UnknownAnchor { .. } => "BAD_ALIAS",
            serde_saphyr::Error::Budget { .. } => "RESOURCE_EXHAUSTION",
            _ => "UNEXPECTED_TOKEN",
        };
        let range = error
            .location()
            .and_then(|location| SourceRange::from_location(input, location));

        Self {
            message: error.to_string(),
            code,
            range,
        }
    }
}

impl SourceRange {
    fn from_span(input: &str, span: &Span) -> Self {
        Self {
            start: marker_byte_offset(input, &span.start),
            end: marker_byte_offset(input, &span.end),
        }
    }

    fn at_marker(input: &str, marker: &Marker) -> Self {
        let start = marker_byte_offset(input, marker);
        let end = input[start..]
            .chars()
            .next()
            .map_or(start, |character| start + character.len_utf8());

        Self { start, end }
    }

    fn from_location(input: &str, location: serde_saphyr::Location) -> Option<Self> {
        let span = location.span();
        let bom_len = usize::from(input.starts_with('\u{feff}')) * '\u{feff}'.len_utf8();
        let source = &input[bom_len..];

        let (start, end) = if let (Some(offset), Some(len)) = (span.byte_offset(), span.byte_len())
        {
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            (start, end)
        } else {
            let start = char_offset_to_byte(source, usize::try_from(span.offset()).ok()?)?;
            let end = char_offset_to_byte(
                source,
                usize::try_from(span.offset().checked_add(span.len())?).ok()?,
            )?;
            (start, end)
        };

        (end <= source.len()).then_some(Self {
            start: start + bom_len,
            end: end + bom_len,
        })
    }
}

fn marker_byte_offset(input: &str, marker: &Marker) -> usize {
    marker
        .byte_offset()
        .filter(|offset| *offset <= input.len() && input.is_char_boundary(*offset))
        .or_else(|| char_offset_to_byte(input, marker.index()))
        .unwrap_or(input.len())
}

fn char_offset_to_byte(input: &str, offset: usize) -> Option<usize> {
    input
        .char_indices()
        .map(|(offset, _)| offset)
        .nth(offset)
        .or_else(|| (offset == input.chars().count()).then_some(input.len()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourcePosition {
    offset: u32,
    line: u32,
    column: u32,
}

fn source_position(input: &str, byte_offset: usize) -> SourcePosition {
    let mut offset = 0_u32;
    let mut line = 1_u32;
    let mut column = 1_u32;
    let mut previous_was_carriage_return = false;

    for character in input[..byte_offset].chars() {
        let width = u32::try_from(character.len_utf16()).unwrap_or(u32::MAX);
        offset = offset.saturating_add(width);

        match character {
            '\r' => {
                line = line.saturating_add(1);
                column = 1;
            }
            '\n' if previous_was_carriage_return => {}
            '\n' => {
                line = line.saturating_add(1);
                column = 1;
            }
            _ => column = column.saturating_add(width),
        }

        previous_was_carriage_return = character == '\r';
    }

    SourcePosition {
        offset,
        line,
        column,
    }
}

fn create_yaml_error<'env>(
    env: &'env Env,
    input: &str,
    error: &ParseError,
) -> napi::Result<Object<'env>> {
    let mut object = env.create_error(Error::new(Status::InvalidArg, error.message.clone()))?;
    object.set("name", "YAMLParseError")?;
    object.set("code", error.code)?;

    if let Some(range) = error.range {
        let start = source_position(input, range.start);
        let end = source_position(input, range.end);
        object.set("pos", [start.offset, end.offset])?;

        let mut start_line = Object::new(env)?;
        start_line.set("line", start.line)?;
        start_line.set("col", start.column)?;
        let mut end_line = Object::new(env)?;
        end_line.set("line", end.line)?;
        end_line.set("col", end.column)?;
        object.set("linePos", vec![start_line, end_line])?;

        let mut start_location = Object::new(env)?;
        start_location.set("offset", start.offset)?;
        start_location.set("line", start.line)?;
        start_location.set("column", start.column)?;
        let mut end_location = Object::new(env)?;
        end_location.set("offset", end.offset)?;
        end_location.set("line", end.line)?;
        end_location.set("column", end.column)?;
        let mut location = Object::new(env)?;
        location.set("start", start_location)?;
        location.set("end", end_location)?;
        object.set("location", location)?;
    }

    Ok(object)
}

fn into_napi_error(env: &Env, input: &str, error: ParseError) -> Error {
    match create_yaml_error(env, input, &error)
        .and_then(|object| Ok(Error::from((&object).into_unknown(env)?)))
    {
        Ok(error) | Err(error) => error,
    }
}

#[derive(Clone, Copy)]
enum YamlSchema {
    /// Resolve nulls, booleans, integers, and floats to their JavaScript types.
    Core,
    /// Preserve every scalar value as a string.
    Failsafe,
}

struct FailsafeParser<'input> {
    input: &'input str,
    events: Parser<'input, StrInput<'input>>,
    peeked: Option<(Event<'input>, Span)>,
    anchors: HashMap<usize, (Value, usize)>,
    nodes: usize,
}

impl<'input> FailsafeParser<'input> {
    fn new(input: &'input str) -> Self {
        Self {
            input,
            events: Parser::new_from_str(input),
            peeked: None,
            anchors: HashMap::new(),
            nodes: 0,
        }
    }

    fn parse(mut self) -> ParseResult<Value> {
        self.expect(|event| matches!(event, Event::StreamStart), "stream start")?;

        if matches!(self.peek()?, Event::StreamEnd) {
            self.next()?;
            return Ok(Value::Null);
        }

        match self.next()? {
            (Event::DocumentStart(..), _) => {}
            (event, span) => {
                return Err(unexpected(self.input, "document start", &event, &span));
            }
        }

        let value = self.parse_node(0)?.0;
        self.expect(|event| matches!(event, Event::DocumentEnd), "document end")?;

        match self.next()? {
            (Event::StreamEnd, _) => {}
            (Event::DocumentStart(..), span) => {
                return Err(ParseError::at_span(
                    self.input,
                    "source contains multiple YAML documents",
                    "MULTIPLE_DOCS",
                    &span,
                ));
            }
            (event, span) => {
                return Err(unexpected(self.input, "stream end", &event, &span));
            }
        }

        if self.next_event()?.is_some() {
            return Err(ParseError::at_end(
                self.input,
                "unexpected events after the YAML stream ended",
            ));
        }

        Ok(value)
    }

    fn parse_node(&mut self, depth: usize) -> ParseResult<(Value, Span)> {
        let (event, span) = self.next()?;

        if depth >= MAX_DEPTH {
            return Err(ParseError::at_span(
                self.input,
                format!("YAML nesting exceeds the limit of {MAX_DEPTH}"),
                "RESOURCE_EXHAUSTION",
                &span,
            ));
        }

        match event {
            Event::Scalar(value, style, anchor, _) => {
                self.add_nodes(1, &span)?;
                let value = if value == "~" && style == ScalarStyle::Plain && span.is_empty() {
                    Value::String(String::new())
                } else {
                    Value::String(value.into_owned())
                };
                self.store_anchor(anchor, &value, 1);
                Ok((value, span))
            }
            Event::SequenceStart(_, anchor, _) => {
                let first_node = self.nodes;
                self.add_nodes(1, &span)?;
                let mut values = Vec::new();

                while !matches!(self.peek()?, Event::SequenceEnd) {
                    values.push(self.parse_node(depth + 1)?.0);
                }
                self.next()?;

                let value = Value::Array(values);
                self.store_anchor(anchor, &value, self.nodes - first_node);
                Ok((value, span))
            }
            Event::MappingStart(_, anchor, _) => {
                let first_node = self.nodes;
                self.add_nodes(1, &span)?;
                let mut values = Map::new();

                while !matches!(self.peek()?, Event::MappingEnd) {
                    let (key, key_span) = self.parse_node(depth + 1)?;
                    let key = stringify_key(&key);

                    match values.entry(key) {
                        Entry::Vacant(entry) => {
                            let value = self.parse_node(depth + 1)?.0;
                            entry.insert(value);
                        }
                        Entry::Occupied(entry) => {
                            return Err(ParseError::at_span(
                                self.input,
                                format!(
                                    "duplicate mapping key: {} at line {} column {}",
                                    entry.key(),
                                    key_span.start.line(),
                                    key_span.start.col() + 1,
                                ),
                                "DUPLICATE_KEY",
                                &key_span,
                            ));
                        }
                    }
                }
                self.next()?;

                let value = Value::Object(values);
                self.store_anchor(anchor, &value, self.nodes - first_node);
                Ok((value, span))
            }
            Event::Alias(anchor) => {
                let Some((value, nodes)) = self.anchors.get(&anchor).cloned() else {
                    return Err(ParseError::at_span(
                        self.input,
                        format!("alias refers to unknown anchor {anchor}"),
                        "BAD_ALIAS",
                        &span,
                    ));
                };
                self.add_nodes(nodes, &span)?;
                Ok((value, span))
            }
            event => Err(unexpected(self.input, "YAML value", &event, &span)),
        }
    }

    fn next(&mut self) -> ParseResult<(Event<'input>, Span)> {
        if let Some(event) = self.peeked.take() {
            return Ok(event);
        }

        self.next_event()?
            .ok_or_else(|| ParseError::at_end(self.input, "unexpected end of YAML input"))
    }

    fn next_event(&mut self) -> ParseResult<Option<(Event<'input>, Span)>> {
        loop {
            match self
                .events
                .next()
                .transpose()
                .map_err(|error| ParseError::from_scan_error(self.input, error))?
            {
                Some((Event::Comment(..), _)) => {}
                event => return Ok(event),
            }
        }
    }

    fn peek(&mut self) -> ParseResult<&Event<'input>> {
        if self.peeked.is_none() {
            self.peeked = self.next_event()?;
        }

        self.peeked
            .as_ref()
            .map(|(event, _)| event)
            .ok_or_else(|| ParseError::at_end(self.input, "unexpected end of YAML input"))
    }

    fn expect(
        &mut self,
        predicate: impl FnOnce(&Event<'input>) -> bool,
        expected: &str,
    ) -> ParseResult<()> {
        let (event, span) = self.next()?;
        if predicate(&event) {
            Ok(())
        } else {
            Err(unexpected(self.input, expected, &event, &span))
        }
    }

    fn add_nodes(&mut self, nodes: usize, span: &Span) -> ParseResult<()> {
        self.nodes = self
            .nodes
            .checked_add(nodes)
            .filter(|nodes| *nodes <= MAX_NODES)
            .ok_or_else(|| {
                ParseError::at_span(
                    self.input,
                    format!("YAML node count exceeds the limit of {MAX_NODES}"),
                    "RESOURCE_EXHAUSTION",
                    span,
                )
            })?;
        Ok(())
    }

    fn store_anchor(&mut self, anchor: usize, value: &Value, nodes: usize) {
        if anchor != 0 {
            self.anchors.insert(anchor, (value.clone(), nodes));
        }
    }
}

fn unexpected(input: &str, expected: &str, event: &Event<'_>, span: &Span) -> ParseError {
    ParseError::at_span(
        input,
        format!("expected {expected}, found {event:?}"),
        "UNEXPECTED_TOKEN",
        span,
    )
}

fn stringify_key(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => format!(
            "[ {} ]",
            values
                .iter()
                .map(stringify_key)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{ {} }}",
            values
                .iter()
                .map(|(key, value)| format!("{key}: {}", stringify_key(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn parse_value(input: &str, schema: Option<YamlSchema>) -> ParseResult<Value> {
    if matches!(schema, Some(YamlSchema::Failsafe)) {
        FailsafeParser::new(input).parse()
    } else {
        serde_saphyr::from_str_with_options(
            input,
            serde_saphyr::options! {
                duplicate_keys: DuplicateKeyPolicy::Error,
            },
        )
        .map_err(|error| ParseError::from_serde_error(input, error))
    }
}

/// Parse a YAML document into a JavaScript value.
///
/// The core schema resolves YAML scalar types. The failsafe schema preserves all scalars as
/// strings. Duplicate mapping keys are rejected in both modes.
///
/// # Errors
///
/// Throws a `YAMLParseError` if the input is not a single valid YAML document or contains
/// duplicate mapping keys. The error includes `code`, `pos`, `linePos`, and `location` properties.
#[napi(ts_return_type = "unknown")]
pub fn parse_yaml(
    env: Env,
    input: String,
    #[napi(ts_arg_type = "'core' | 'failsafe'")] schema: Option<String>,
) -> napi::Result<Unknown<'static>> {
    let schema = match schema.as_deref() {
        None | Some("core") => Some(YamlSchema::Core),
        Some("failsafe") => Some(YamlSchema::Failsafe),
        Some(schema) => {
            return Err(AnthelionError::invalid(format!("Invalid YAML schema {schema:?}")).into());
        }
    };
    let value =
        parse_value(&input, schema).map_err(|error| into_napi_error(&env, &input, error))?;
    // V8's JSON parser is substantially faster for large mappings than constructing each
    // property through N-API one at a time.
    let json = serde_json::to_string(&value).map_err(|error| {
        AnthelionError::failure(ErrorCode::YamlParseFailed, Report::from(error))
    })?;
    let global = env.get_global()?;
    let json_object: Object = global.get_named_property("JSON")?;
    let parse: Function<String, Unknown<'static>> = json_object.get_named_property("parse")?;
    parse.call(json)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{SourcePosition, SourceRange, YamlSchema, parse_value, source_position};

    #[test]
    fn parses_core_schema_scalars() {
        assert_eq!(
            parse_value("enabled: true\ncount: 3\n", None).unwrap(),
            json!({ "enabled": true, "count": 3 }),
        );
    }

    #[test]
    fn preserves_failsafe_scalars() {
        assert_eq!(
            parse_value(
                "null: null\ntilde: ~\nbool: true\nfloat: 1.0\nleading: 001\nempty:\n",
                Some(YamlSchema::Failsafe),
            )
            .unwrap(),
            json!({
                "null": "null",
                "tilde": "~",
                "bool": "true",
                "float": "1.0",
                "leading": "001",
                "empty": "",
            }),
        );
    }

    #[test]
    fn rejects_duplicate_keys() {
        let input = "key: first\nkey: second\n";
        let expected_range = Some(SourceRange { start: 11, end: 14 });

        let core_error = parse_value(input, None).unwrap_err();
        assert_eq!(core_error.code, "DUPLICATE_KEY");
        assert_eq!(core_error.range, expected_range);

        let failsafe_error = parse_value(input, Some(YamlSchema::Failsafe)).unwrap_err();
        assert_eq!(failsafe_error.code, "DUPLICATE_KEY");
        assert_eq!(failsafe_error.range, expected_range);
    }

    #[test]
    fn resolves_failsafe_aliases() {
        assert_eq!(
            parse_value(
                "base: &base\n  version: 1.0\ncopy: *base\n",
                Some(YamlSchema::Failsafe),
            )
            .unwrap(),
            json!({
                "base": { "version": "1.0" },
                "copy": { "version": "1.0" },
            }),
        );
    }

    #[test]
    fn handles_empty_failsafe_documents() {
        assert_eq!(
            parse_value("", Some(YamlSchema::Failsafe)).unwrap(),
            Value::Null,
        );
        assert_eq!(
            parse_value("---", Some(YamlSchema::Failsafe)).unwrap(),
            Value::String(String::new()),
        );
    }

    #[test]
    fn rejects_multiple_documents() {
        let input = "---\na: 1\n---\nb: 2\n";

        let core_error = parse_value(input, None).unwrap_err();
        assert_eq!(core_error.code, "MULTIPLE_DOCS");
        assert!(core_error.range.is_some());

        let failsafe_error = parse_value(input, Some(YamlSchema::Failsafe)).unwrap_err();
        assert_eq!(failsafe_error.code, "MULTIPLE_DOCS");
        assert!(failsafe_error.range.is_some());
    }

    #[test]
    fn reports_javascript_source_positions() {
        let input = "😀: value\r\nkey";

        assert_eq!(
            source_position(input, input.find("key").unwrap()),
            SourcePosition {
                offset: 11,
                line: 2,
                column: 1,
            },
        );
    }
}
