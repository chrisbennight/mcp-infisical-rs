//! Deterministic local search over the served operation catalog.

pub(crate) const REVIEWED_ALIASES: &[(&str, &str)] = &[
    (
        "secretRotations.sql.rotate",
        "rotate database password credentials",
    ),
    (
        "dynamicSecretLeases.create",
        "create temporary database credentials",
    ),
    ("secrets.reveal", "read reveal secret value password"),
    ("sshCertificates.sign", "sign ssh certificate public key"),
    ("kms.encrypt", "encrypt data"),
];

pub(crate) fn query_terms(query: &str) -> Result<Vec<String>, &'static str> {
    if query.chars().count() > 128 {
        return Err("query must contain at most 128 characters");
    }
    let terms: Vec<_> = query
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect();
    if terms.is_empty() {
        return Err("query must contain a word; omit query to browse operations");
    }
    Ok(terms)
}

pub(crate) fn score(terms: &[String], name: &str, description: &str) -> Option<u32> {
    if terms.is_empty() {
        return Some(0);
    }
    let normalized_name = name.to_lowercase();
    let normalized_description = description.to_lowercase();
    let aliases = REVIEWED_ALIASES
        .iter()
        .find_map(|(operation, aliases)| (*operation == name).then_some(*aliases))
        .unwrap_or_default();
    terms.iter().try_fold(0, |score, term| {
        let weight = if normalized_name.contains(term) {
            20
        } else if aliases.contains(term) {
            10
        } else if normalized_description.contains(term) {
            1
        } else {
            return None;
        };
        Some(score + weight)
    })
}

pub(crate) fn brief(description: &str) -> String {
    let sentence = description
        .split_once(". ")
        .map_or(description, |(first, _)| first);
    if sentence.chars().count() <= 160 {
        sentence.to_owned()
    } else {
        sentence.chars().take(159).chain(['…']).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_intent_aliases_match_all_query_terms() {
        let terms = query_terms("Rotate database password").unwrap();
        assert!(score(&terms, "secretRotations.sql.rotate", "Rotate credentials.").is_some());
        assert!(score(&terms, "secrets.reveal", "Read a password.").is_none());
    }

    #[test]
    fn bounds_count_unicode_characters_and_summaries_do_not_split_them() {
        assert!(query_terms(&"é".repeat(128)).is_ok());
        assert!(query_terms(&"é".repeat(129)).is_err());
        assert!(query_terms("!? ").is_err());
        assert_eq!(brief(&"é".repeat(161)).chars().count(), 160);
        assert_eq!(brief("First sentence. More detail."), "First sentence");
    }
}
