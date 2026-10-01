# Documentation style

These documents exist to be read. A page that nobody finishes has failed,
however accurate it is. This guide is the contract;
[`tests/lint_docs.sh`](../tests/lint_docs.sh) enforces the mechanical half
of it on every pull request.

## 1. Write for a reader with a task

Before writing a paragraph, name the reader and what they are trying to
do: "an embedder wiring a BGP session into an event loop", "an operator
whose session will not come up". If you cannot name them, the paragraph
has no job and should be deleted.

Open every document with one short paragraph that says what the document
covers and who should read it. No preamble about how important the topic
is.

## 2. Sentences

One idea per sentence. If a sentence has three commas and two
parentheses, split it.

- **Active voice.** "The codec merges `AS4_PATH` into `AS_PATH`", not
  "`AS4_PATH` is merged into `AS_PATH` by the codec".
- **Name the actor.** "The router drops the route", not "the route is
  dropped".
- **Delete the throat-clearing.** "It is worth noting that", "Note
  that", "In order to", "It should be noted that", "As we can see" —
  cut them; the sentence is fine without.
- **Delete the adjectives.** `robust`, `seamless`, `powerful`,
  `comprehensive`, `state-of-the-art`, `production-grade`, `fully` —
  none of them carry information. Say what the code does instead.
- **Define jargon on first use, in the same sentence.** "MRAI (the
  minimum route advertisement interval)"; after that, use the term.
  Never stack two undefined acronyms in one clause.
- **Prefer a concrete number or a pointer over a qualifier.** "Sends the
  next UPDATE after `mrai` elapses" beats "handles advertisement timing
  appropriately".

## 3. Say what is true today

A document is not a changelog. Anything that changes on its own must not
be written down in prose:

| Do not write | Write instead |
| --- | --- |
| a literal dependency version, e.g. a pinned `lr-bgp = "…"` | `lr-bgp = "<version>"`, and point at `Cargo.toml` |
| "as of March 2025" | nothing — state the behaviour |
| "18 crates", "69 labs" | "the crates under `crates/`" |
| "currently", "now", "at the time of writing" | the present tense |
| a commit hash | the file and line, or nothing |
| the list of open issues | a link to the issues page |
| "this was fixed in #123" | the changelog already says so |

Release history belongs in [`../CHANGELOG.md`](../CHANGELOG.md), and
version policy in [`RELEASE-PLAN.md`](RELEASE-PLAN.md). Nothing else
carries a version number.

Likewise, do not record "landed" markers (`~~like this~~`) in a plan.
When work lands, delete the item from the plan; the commit and the
changelog are the record.

## 4. Layout

The lint enforces these; they are not suggestions.

- **Wrap prose at 80 columns.** Not 79, not "around 80". A line whose
  overflow is one unbreakable token is allowed, and so are fenced code,
  indented code, table rows and bare URLs — none of those can be wrapped
  without changing what they mean.
- **Fence every code block and tag its language** (` ```sh `, ` ```rust `,
  ` ```toml `, ` ```text `).
- **One level-1 heading per file**, at the top. Use `##` and below for
  structure.
- **No tabs. No trailing whitespace.** Indent nested lists with two
  spaces, matching the surrounding file.
- **A table cell holds a few words.** If a cell needs a paragraph, the
  content wants a list or its own section. Tables wider than the 80-column
  budget are a sign of that.
- Prefer relative links (`../README.md`) over bare paths in prose, and
  check they resolve — the lint fails on a dead relative link.

## 5. Point at the code

The code is the source of truth. When a document and the code disagree,
the document is wrong; fix it in the same change.

- Name the crate, module, type or function the reader should look at:
  `lr-bgp::BgpPeer::step`.
- Do not paraphrase a signature. If the signature matters, show it.
- Do not copy a whole file into a document. Show the two lines that
  matter and link the rest.
- Cite the RFC section when explaining protocol behaviour:
  `RFC 4271 §9.1.2`. Keep the citation next to the claim it supports.

## 6. Where content goes

| Content | Document |
| --- | --- |
| What the project is, how to build it | [`../README.md`](../README.md) |
| Your first working program | [`tutorial.md`](tutorial.md) |
| Every public type, by crate | [`api/`](api/) |
| How the pieces fit together | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Running the daemon | [`lr-cli.md`](lr-cli.md), [`RUNBOOK.md`](RUNBOOK.md) |
| Configuration and filter syntax | [`config_dsl_grammar.md`](config_dsl_grammar.md), [`filter_dsl_grammar.md`](filter_dsl_grammar.md) |
| What is implemented | [`STATUS.md`](STATUS.md), [`RFC_MAP.md`](RFC_MAP.md) |
| What is planned | [`ROADMAP.md`](ROADMAP.md) |
| What changed, per release | [`../CHANGELOG.md`](../CHANGELOG.md) |
| Scenario walkthroughs | [`examples/`](examples/) |
| Open design questions | [`research/`](research/) |

## 7. Run the checks

```sh
tests/lint_docs.sh          # wrap, tabs, links, release stamps
tests/lint_interop_doc.sh   # docs/INTEROP.md vs tests/interop/
```

Both run in the `lint` CI job. Run them before opening a pull request.

## 8. Before you commit a document

1. Does the first paragraph tell the reader whether this page is for
   them?
2. Can you delete any sentence without losing information? Delete it.
3. Is every version number, date and count gone?
4. Does every code block compile, or is it marked as illustrative?
5. Does every relative link resolve?
6. Do the claims still match the code? Open the file and check.
