const PREFIX: &str = "ETRS-RF-SKIP/1;";
const RESERVED_PREFIX: &str = "ETRS-RF-SKIP/";
pub const MAX_REVERSE_ROWS: usize = 128;
pub const MAX_SKIPPED_ROWS: usize = 32;
pub const MAX_REPORT_LEN: usize = 256;
const _: () = assert!(PREFIX.len() + MAX_SKIPPED_ROWS * 6 <= MAX_REPORT_LEN);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    Resolve,
    Bind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkippedRow {
    pub index: usize,
    pub reason: SkipReason,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReportError;

impl std::fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "malformed reverse forwarding skip report")
    }
}

impl std::error::Error for ReportError {}

pub fn encode_skipped_rows(rows: &[SkippedRow]) -> Result<String, ReportError> {
    if rows.is_empty() || rows.len() > MAX_SKIPPED_ROWS {
        return Err(ReportError);
    }
    let mut encoded = String::from(PREFIX);
    let mut previous = None;
    for row in rows {
        if row.index >= MAX_REVERSE_ROWS || previous.is_some_and(|index| index >= row.index) {
            return Err(ReportError);
        }
        if previous.is_some() {
            encoded.push(',');
        }
        previous = Some(row.index);
        encoded.push_str(&row.index.to_string());
        encoded.push(':');
        encoded.push(match row.reason {
            SkipReason::Resolve => 'R',
            SkipReason::Bind => 'B',
        });
    }
    (encoded.len() <= MAX_REPORT_LEN)
        .then_some(encoded)
        .ok_or(ReportError)
}

pub fn decode_skipped_rows(
    encoded: &str,
    row_count: usize,
) -> Result<Option<Vec<SkippedRow>>, ReportError> {
    if !encoded.starts_with(RESERVED_PREFIX) {
        return Ok(None);
    }
    if encoded.len() > MAX_REPORT_LEN || row_count > MAX_REVERSE_ROWS {
        return Err(ReportError);
    }
    let body = encoded.strip_prefix(PREFIX).ok_or(ReportError)?;
    if body.is_empty() {
        return Err(ReportError);
    }
    let mut rows = Vec::new();
    let mut previous = None;
    for field in body.split(',') {
        let (raw_index, raw_reason) = field.split_once(':').ok_or(ReportError)?;
        let index = raw_index.parse::<usize>().map_err(|_| ReportError)?;
        if raw_index != index.to_string()
            || index >= row_count
            || previous.is_some_and(|previous| previous >= index)
        {
            return Err(ReportError);
        }
        let reason = match raw_reason {
            "R" => SkipReason::Resolve,
            "B" => SkipReason::Bind,
            _ => return Err(ReportError),
        };
        rows.push(SkippedRow { index, reason });
        previous = Some(index);
    }
    if rows.is_empty() || rows.len() > MAX_SKIPPED_ROWS {
        return Err(ReportError);
    }
    Ok(Some(rows))
}

#[cfg(test)]
mod tests {
    use super::{decode_skipped_rows, encode_skipped_rows, SkipReason, SkippedRow, MAX_REPORT_LEN};

    #[test]
    fn report_round_trips_bounded_machine_codes() {
        let rows = [
            SkippedRow {
                index: 0,
                reason: SkipReason::Resolve,
            },
            SkippedRow {
                index: 31,
                reason: SkipReason::Bind,
            },
        ];

        let encoded = encode_skipped_rows(&rows).unwrap();
        let decoded = decode_skipped_rows(&encoded, 32).unwrap().unwrap();

        assert_eq!(decoded, rows);
        assert!(encoded.is_ascii());
        assert!(encoded.len() <= MAX_REPORT_LEN);
    }

    #[test]
    fn unrelated_error_is_not_a_report() {
        assert_eq!(decode_skipped_rows("Permission denied", 1).unwrap(), None);
    }

    #[test]
    fn malformed_reports_fail_closed() {
        for report in [
            "ETRS-RF-SKIP/1;",
            "ETRS-RF-SKIP/1;0:B,",
            "ETRS-RF-SKIP/1;0:B,0:R",
            "ETRS-RF-SKIP/1;1:B",
            "ETRS-RF-SKIP/2;0:B",
            "ETRS-RF-SKIP/1;0:X",
            "ETRS-RF-SKIP/1;00:B",
            "ETRS-RF-SKIP/1;0:B\n",
        ] {
            assert!(decode_skipped_rows(report, 1).is_err(), "{report:?}");
        }
    }

    #[test]
    fn oversized_and_truncated_reports_fail_closed() {
        let oversized = format!("ETRS-RF-SKIP/1;{}", "0:B,".repeat(MAX_REPORT_LEN));
        assert!(decode_skipped_rows(&oversized, 128).is_err());
        assert!(decode_skipped_rows("ETRS-RF-SKIP/1;0", 1).is_err());
    }
}
