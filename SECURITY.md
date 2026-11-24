# Security policy

## Report a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/dominicferri/mactriage/security/advisories/new>.

Do not describe a security problem in a public issue.

## Scope

mactriage is a read-only tool. It runs system tools by their full path with a
time limit, and a privileged scan runs as root. Reports about these areas are
welcome:

- a way to make mactriage run a program that another account can replace,
  above all under `sudo`
- output that lets text from a report file or the unified log put control
  characters into a terminal or into an HTML report
- files that mactriage writes with permissions or at paths that another
  account can abuse

## Supported versions

Only the latest release gets fixes.
