//! Official Apple documentation behind each finding.
//!
//! Every URL below was fetched and every `says` summary was checked against
//! the fetched page before release. `says` is a plain-English summary, not a
//! quote. Rules for which Apple publishes nothing are listed in
//! [`NO_APPLE_DOC`] with the source mactriage relies on instead, so a missing
//! reference is always a deliberate statement and never an oversight.

use crate::report::{Finding, Reference};

/// One Apple page.
pub struct Doc {
    pub title: &'static str,
    pub url: &'static str,
}

/// One cited passage: the page and what it says.
pub struct Cite {
    pub doc: &'static Doc,
    pub says: &'static str,
}

impl Cite {
    pub fn reference(&self) -> Reference {
        Reference {
            title: self.doc.title.into(),
            url: self.doc.url.into(),
            apple_says: self.says.into(),
        }
    }
}

/// A decoded crash-report value (exception type, signal, termination code).
pub struct Decoded {
    /// Specific advice that replaces the generic crash advice, if any.
    pub next_step: Option<&'static str>,
    pub cite: Cite,
}

impl Decoded {
    pub fn reference(&self) -> Reference {
        self.cite.reference()
    }
}

/// Add `r` unless the same passage of the same page is already listed. One
/// page can carry several different facts (Apple's SIGKILL page explains both
/// the signal and each termination code), so the URL alone is not the key.
pub fn push_unique(out: &mut Vec<Reference>, r: Reference) {
    if !out
        .iter()
        .any(|x| x.url == r.url && x.apple_says == r.apple_says)
    {
        out.push(r);
    }
}

/// Append the rule's references after any report-specific ones.
pub fn attach(f: &mut Finding) {
    for c in rule_cites(&f.rule_id) {
        push_unique(&mut f.references, c.reference());
    }
}

include!("apple_docs_data.rs");
