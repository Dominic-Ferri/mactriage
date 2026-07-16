//! Conservative recovery disposition built from existing scan findings.
//!
//! A clean install is destructive and cannot be justified by a severity score.
//! Firmware, hardware, storage, and third-party causes take precedence. The
//! assessment names the next recovery tier and the manual gates that must be
//! satisfied before an erase is even considered.

use crate::report::{
    CleanInstallStatus, Confidence, Finding, RecoveryAssessment, RecoveryRecommendation, Report,
    Severity,
};

pub fn assess(report: &Report, full_recovery_coverage: bool) -> RecoveryAssessment {
    // Contradiction gate: when the live Disk vital says SMART verified, a
    // keyword-derived pile of log I/O errors alone must not escalate the Mac
    // to hardware service (2026-09-08 field report did exactly that).
    let smart_verified = report
        .vitals
        .iter()
        .any(|v| v.label == "Disk" && v.value.contains("SMART verified"));
    assess_findings(
        &report.findings,
        report.complete,
        full_recovery_coverage && report.host.root,
        &report.host.chip,
        smart_verified,
    )
}

fn assess_findings(
    findings: &[Finding],
    scan_complete: bool,
    full_recovery_coverage: bool,
    chip: &str,
    smart_verified: bool,
) -> RecoveryAssessment {
    let firmware_panic = findings.iter().any(is_firmware_panic);
    let hardware_panic = findings.iter().any(is_hardware_panic);
    // A High SSD-wear finding (critical warning, spare below threshold, media
    // errors, or endurance exhausted) is storage-hardware evidence like SMART.
    let smart_failure =
        has_rule(findings, "snap.smart") || has_severe_rule(findings, "snap.ssd_wear");
    // Log-derived I/O evidence is hardware-grade only when SMART does not
    // directly contradict it; otherwise it falls through to the software tiers.
    let severe_io = has_severe_rule(findings, "log.io_errors") && !smart_verified;
    let power_hardware = findings.iter().any(|f| {
        f.rule_id == "log.shutdown_cause"
            && f.severity >= Severity::High
            && contains_any(
                &finding_text(f),
                &[
                    "bridgeos",
                    "pmu",
                    "thermal emergency",
                    "thermal forced",
                    "power supply fault",
                    "incorrect current",
                    "battery fault",
                    "cell undervoltage",
                    "spike/surge",
                ],
            )
    });
    let panic_kext = has_rule(findings, "correlate.panic_kext");
    let panic_count: u32 = findings
        .iter()
        .filter(|f| f.rule_id == "file.kernel_panic")
        .map(|f| f.count.max(1))
        .sum();
    let update_failures = rule_count(findings, "log.software_update");
    let backup_problem = has_rule(findings, "snap.tm_stale") || has_rule(findings, "log.backupd");
    let mdm_present = has_rule(findings, "posture.mdm_profiles");
    let repairable_software = findings.iter().any(|f| {
        matches!(
            f.rule_id.as_str(),
            "correlate.crash_loop"
                | "correlate.story"
                | "audit.launch_broken"
                | "audit.btm_orphan"
                | "log.kext"
                | "log.launchd_services"
        ) && f.severity >= Severity::Medium
    });
    let os_wide_failure = findings.iter().any(|f| {
        matches!(
            f.rule_id.as_str(),
            "log.watchdog" | "log.gpu_reset" | "boot.slow_boot" | "log.io_errors"
        ) && f.severity >= Severity::High
    });

    let mut assessment = if firmware_panic
        || hardware_panic
        || smart_failure
        || severe_io
        || power_hardware
    {
        let mut reasons = Vec::new();
        if hardware_panic {
            reasons.push(
                "Kernel panic evidence names a hardware-reported fault (CPU catastrophic error, machine check, or ECC memory error)."
                    .into(),
            );
        }
        if firmware_panic {
            reasons.push(
                "Kernel panic evidence names a firmware or coprocessor path such as SEP, BridgeOS, SMC, ANS, DCP, AOP, or RTKit."
                    .into(),
            );
        }
        if smart_failure || severe_io {
            reasons.push(
                "SMART, SSD health-log, or repeated storage I/O evidence points to a disk, controller, or filesystem path that erasing cannot repair."
                    .into(),
            );
        }
        if power_hardware {
            reasons.push(
                "The shutdown record identifies a firmware, thermal, or power-management failure."
                    .into(),
            );
        }
        RecoveryAssessment {
            recommendation: RecoveryRecommendation::FirmwareOrHardwareFirst,
            clean_install: CleanInstallStatus::NotIndicated,
            confidence: Confidence::High,
            reasons,
            blockers: Vec::new(),
            next_steps: firmware_steps(chip),
            required_before_clean_install: clean_install_gates(),
        }
    } else if panic_kext {
        RecoveryAssessment {
            recommendation: RecoveryRecommendation::RepairSoftwareFirst,
            clean_install: CleanInstallStatus::NotIndicated,
            confidence: Confidence::High,
            reasons: vec![
                "A currently loaded third-party kernel extension appears in a panic backtrace; repair or remove that component before changing macOS."
                    .into(),
            ],
            blockers: Vec::new(),
            next_steps: vec![
                "Identify the product that owns the named extension, then update or remove it using the vendor's supported procedure.".into(),
                "Retest with that extension absent before escalating to an operating-system reinstall.".into(),
            ],
            required_before_clean_install: clean_install_gates(),
        }
    } else if panic_count >= 2 {
        RecoveryAssessment {
            recommendation: RecoveryRecommendation::FirmwareOrHardwareFirst,
            clean_install: CleanInstallStatus::NotYetJustified,
            confidence: Confidence::Medium,
            reasons: vec![format!(
                "{panic_count} kernel panic events were found; repeated kernel panics require firmware and hardware checks before reinstalling macOS."
            )],
            blockers: Vec::new(),
            next_steps: firmware_steps(chip),
            required_before_clean_install: clean_install_gates(),
        }
    } else if !scan_complete || !full_recovery_coverage {
        let mut blockers = Vec::new();
        if !scan_complete {
            blockers.push(
                "The scan is incomplete; one or more diagnostic sources failed, timed out, or were denied."
                    .into(),
            );
        }
        if !full_recovery_coverage {
            blockers.push(
                "Recovery-critical categories, the unified log, or privileged panic records were not fully scanned."
                    .into(),
            );
        }
        RecoveryAssessment {
            recommendation: RecoveryRecommendation::CollectMoreEvidence,
            clean_install: CleanInstallStatus::Blocked,
            confidence: Confidence::Low,
            reasons: vec![
                "A partial scan cannot distinguish operating-system corruption from firmware, hardware, or third-party causes."
                    .into(),
            ],
            blockers,
            next_steps: vec![
                "Run the default full scan with sudo from a Terminal that has Full Disk Access, without --only, --skip, or --no-log.".into(),
                "Verify the backup destination and rerun with a window that includes the failure.".into(),
            ],
            required_before_clean_install: clean_install_gates(),
        }
    } else if repairable_software {
        RecoveryAssessment {
            recommendation: RecoveryRecommendation::RepairSoftwareFirst,
            clean_install: CleanInstallStatus::NotIndicated,
            confidence: Confidence::Medium,
            reasons: vec![
                "The strongest evidence points to a specific app, service, launch item, or extension rather than system-wide macOS corruption."
                    .into(),
            ],
            blockers: Vec::new(),
            next_steps: vec![
                "Repair, update, or remove the named component and reproduce the original failure before escalating.".into(),
                "Use Safe Mode and a clean user account to separate third-party and per-user state from the operating system.".into(),
            ],
            required_before_clean_install: clean_install_gates(),
        }
    } else if update_failures > 0 || panic_count == 1 || os_wide_failure {
        let mut reasons = Vec::new();
        if update_failures > 0 {
            reasons.push(format!(
                "Software Update recorded {update_failures} failure event(s), but an update error alone does not prove the system volume needs erasing."
            ));
        }
        if panic_count == 1 {
            reasons.push(
                "One kernel panic was found; a single event needs reproduction and hardware checks before an erase decision."
                    .into(),
            );
        }
        if os_wide_failure {
            reasons.push(
                "The scan found an OS-wide watchdog, GPU, boot, or storage failure without a proven third-party cause."
                    .into(),
            );
        }
        RecoveryAssessment {
            recommendation: RecoveryRecommendation::ReinstallMacosInPlace,
            clean_install: CleanInstallStatus::NotYetJustified,
            confidence: Confidence::Medium,
            reasons,
            blockers: Vec::new(),
            next_steps: vec![
                "Verify a current full backup and run Apple Diagnostics before changing macOS.".into(),
                "Reproduce in Safe Mode and a clean user account; if it remains system-wide, reinstall macOS from Recovery without erasing data.".into(),
                "Consider an erase only if the same issue survives that in-place reinstall and every clean-install gate below is satisfied.".into(),
            ],
            required_before_clean_install: clean_install_gates(),
        }
    } else {
        RecoveryAssessment {
            recommendation: RecoveryRecommendation::NoEraseNeeded,
            clean_install: CleanInstallStatus::NotIndicated,
            confidence: Confidence::High,
            reasons: vec![
                "No OS-wide failure pattern currently justifies reinstalling or erasing macOS."
                    .into(),
            ],
            blockers: Vec::new(),
            next_steps: vec![
                "Address any individual findings and reproduce the original complaint before escalating recovery.".into(),
            ],
            required_before_clean_install: Vec::new(),
        }
    };

    if backup_problem && assessment.recommendation != RecoveryRecommendation::NoEraseNeeded {
        assessment.blockers.push(
            "No current successful full backup is proven; do not erase or use DFU Restore.".into(),
        );
        if assessment.clean_install == CleanInstallStatus::NotYetJustified {
            assessment.clean_install = CleanInstallStatus::Blocked;
        }
    }
    if mdm_present && assessment.recommendation != RecoveryRecommendation::NoEraseNeeded {
        assessment.reasons.push(
            "Configuration profiles are installed; an erase may reenroll the Mac and restore the same managed settings."
                .into(),
        );
    }

    assessment
}

fn firmware_steps(chip: &str) -> Vec<String> {
    let mut steps = vec![
        "Verify a current full backup before firmware recovery or service.".into(),
        format!(
            "{}, with external devices disconnected.",
            crate::util::apple_diagnostics_step()
        ),
    ];
    if chip.to_ascii_lowercase().contains("apple") {
        steps.push(
            "From another Mac, perform a DFU Revive first; DFU Restore erases data and requires separate approval."
                .into(),
        );
    } else {
        steps.push(
            "For Apple silicon or a T2 Mac, perform a DFU Revive before considering DFU Restore."
                .into(),
        );
    }
    steps.push(
        "If the same failure signal continues after Revive, seek logic-board, storage, or power service."
            .into(),
    );
    steps
}

fn clean_install_gates() -> Vec<String> {
    vec![
        "A current full backup has been read back or test-restored.".into(),
        "Apple Diagnostics passes, or the identified hardware fault has been repaired.".into(),
        "The original issue reproduces in Safe Mode.".into(),
        "The original issue reproduces in a newly created user account.".into(),
        "A non-erasing macOS reinstall completed and the same issue still reproduces.".into(),
    ]
}

fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule_id == rule_id)
}

fn has_severe_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings
        .iter()
        .any(|f| f.rule_id == rule_id && f.severity >= Severity::High)
}

fn rule_count(findings: &[Finding], rule_id: &str) -> u32 {
    findings
        .iter()
        .filter(|f| f.rule_id == rule_id)
        .map(|f| f.count.max(1))
        .sum()
}

fn is_firmware_panic(finding: &Finding) -> bool {
    finding.rule_id == "file.kernel_panic"
        && contains_any(&finding_text(finding), crate::files::FIRMWARE_PANIC_MARKERS)
}

/// Set by the panic classifier (files.rs) when the panic string carries a
/// hardware-reported fault marker.
fn is_hardware_panic(finding: &Finding) -> bool {
    finding.rule_id == "file.kernel_panic"
        && finding
            .evidence
            .iter()
            .any(|e| e.source == "panic classifier" && e.excerpt.starts_with("hardware-suspect"))
}

fn finding_text(finding: &Finding) -> String {
    let evidence = finding
        .evidence
        .iter()
        .map(|e| format!("{} {}", e.source, e.excerpt))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} {} {} {}",
        finding.rule_id, finding.summary, finding.detail, evidence
    )
    .to_ascii_lowercase()
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Evidence, Finding, Severity};

    #[test]
    fn sep_panics_override_clean_install() {
        let mut panic = Finding::new(
            "file.kernel_panic",
            Severity::Critical,
            "panic",
            "Kernel panic — SEP Panic: :sks/sks",
        );
        panic.count = 3;
        panic.evidence.push(Evidence {
            source: "panic report".into(),
            excerpt: "AppleSEPManager in backtrace".into(),
        });
        let backup = Finding::new(
            "snap.tm_stale",
            Severity::Low,
            "backups",
            "No Time Machine destination",
        );
        let assessment = assess_findings(&[panic, backup], true, true, "Apple M2", false);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::FirmwareOrHardwareFirst
        );
        assert_eq!(assessment.clean_install, CleanInstallStatus::NotIndicated);
        assert_eq!(assessment.confidence, Confidence::High);
        assert!(assessment.blockers.iter().any(|b| b.contains("backup")));
    }

    #[test]
    fn third_party_panic_extension_is_repaired_first() {
        let finding = Finding::new(
            "correlate.panic_kext",
            Severity::High,
            "panic",
            "Loaded kext appears in panic",
        );
        let assessment = assess_findings(&[finding], true, true, "Apple M3", false);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::RepairSoftwareFirst
        );
        assert_eq!(assessment.clean_install, CleanInstallStatus::NotIndicated);
    }

    #[test]
    fn incomplete_scan_blocks_erase_decision() {
        let assessment = assess_findings(&[], false, false, "Apple M4", false);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::CollectMoreEvidence
        );
        assert_eq!(assessment.clean_install, CleanInstallStatus::Blocked);
        assert_eq!(assessment.confidence, Confidence::Low);
    }

    #[test]
    fn update_failure_recommends_non_erasing_reinstall() {
        let update = Finding::new(
            "log.software_update",
            Severity::Medium,
            "updates",
            "Software Update failure",
        );
        let assessment = assess_findings(&[update], true, true, "Apple M2", false);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::ReinstallMacosInPlace
        );
        assert_eq!(
            assessment.clean_install,
            CleanInstallStatus::NotYetJustified
        );
    }

    #[test]
    fn stale_backup_blocks_reinstall_escalation() {
        let update = Finding::new(
            "log.software_update",
            Severity::Medium,
            "updates",
            "Software Update failure",
        );
        let backup = Finding::new(
            "snap.tm_stale",
            Severity::High,
            "backups",
            "Backup is stale",
        );
        let assessment = assess_findings(&[update, backup], true, true, "Apple M2", false);
        assert_eq!(assessment.clean_install, CleanInstallStatus::Blocked);
    }

    // 2026-09-08 field report: log.io_errors (high) escalated a Mac whose Disk
    // vital said "SMART verified" straight to DFU Revive / hardware service.
    #[test]
    fn smart_verified_blocks_log_only_hardware_escalation() {
        let io = Finding::new(
            "log.io_errors",
            Severity::High,
            "i/o",
            "Disk / APFS I/O errors in the log (13 events)",
        );
        let gated = assess_findings(std::slice::from_ref(&io), true, true, "Apple M4", true);
        assert_ne!(
            gated.recommendation,
            RecoveryRecommendation::FirmwareOrHardwareFirst,
            "SMART-verified vitals must gate log-only I/O escalation"
        );
        // Without the contradicting vital the escalation still happens.
        let ungated = assess_findings(&[io], true, true, "Apple M4", false);
        assert_eq!(
            ungated.recommendation,
            RecoveryRecommendation::FirmwareOrHardwareFirst
        );
    }

    #[test]
    fn failing_ssd_health_log_is_hardware_first() {
        let high = Finding::new(
            "snap.ssd_wear",
            Severity::High,
            "disk",
            "SSD health: 3 unrecovered media/data-integrity error(s) recorded",
        );
        // Even with the macOS SMART vital still "verified".
        let assessment = assess_findings(&[high], true, true, "Apple M5", true);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::FirmwareOrHardwareFirst
        );
        assert!(assessment
            .reasons
            .iter()
            .any(|r| r.contains("SSD health-log")));
        let medium = Finding::new(
            "snap.ssd_wear",
            Severity::Medium,
            "disk",
            "SSD health: 85% of rated write endurance used",
        );
        let assessment = assess_findings(&[medium], true, true, "Apple M5", true);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::NoEraseNeeded,
            "endurance wear alone is not a recovery escalation"
        );
    }

    #[test]
    fn classifier_hardware_panic_is_hardware_first() {
        let mut panic = Finding::new(
            "file.kernel_panic",
            Severity::Critical,
            "panic",
            "Kernel panic — x86 CPU CATERR detected",
        );
        panic.evidence.push(Evidence {
            source: "panic classifier".into(),
            excerpt: "hardware-suspect: Intel CPU / logic board (CATERR) (marker \"caterr\")"
                .into(),
        });
        let assessment = assess_findings(&[panic], true, true, "Intel(R) Core(TM) i7", false);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::FirmwareOrHardwareFirst
        );
        assert_eq!(assessment.confidence, Confidence::High);
        assert!(assessment
            .reasons
            .iter()
            .any(|r| r.contains("hardware-reported fault")));
        // Negative control: the same single panic without the classifier tag
        // stays at the one-panic reinstall tier.
        let plain = Finding::new(
            "file.kernel_panic",
            Severity::Critical,
            "panic",
            "Kernel panic — Kernel trap",
        );
        let assessment = assess_findings(&[plain], true, true, "Apple M5", false);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::ReinstallMacosInPlace
        );
    }

    #[test]
    fn healthy_complete_scan_does_not_recommend_erase() {
        let assessment = assess_findings(&[], true, true, "Apple M4", false);
        assert_eq!(
            assessment.recommendation,
            RecoveryRecommendation::NoEraseNeeded
        );
        assert_eq!(assessment.clean_install, CleanInstallStatus::NotIndicated);
    }
}
