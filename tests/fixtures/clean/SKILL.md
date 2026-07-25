---
name: markdown-tidy
description: Tidy and reformat Markdown documents for consistent style.
---

# Markdown Tidy

This skill reformats Markdown files: it normalizes heading levels, wraps long
lines at 80 columns, and ensures a single blank line between blocks.

## Usage

Point the skill at a `.md` file and it returns a cleaned version. It does not
read anything outside the file you give it and makes no network calls.

## Notes

- Preserves fenced code blocks verbatim.
- Leaves front-matter untouched.
