#[must_use]
pub fn random_name() -> String {
    petname::petname(2, "-").unwrap_or_else(|| "unnamed".to_string())
}
