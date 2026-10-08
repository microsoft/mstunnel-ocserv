# ocserv -- Information about our contribution rules and coding style

 Anyone is welcome to contribute to ocserv. You can either take up
tasks from our [planned list](https://gitlab.com/openconnect/ocserv/-/milestones),
or surprise us with enhancement we didn't plan for. In all cases be prepared
to defend and justify your enhancements, and get through few rounds
of changes.

We try to stick to the following rules, so when contributing please
try to follow them too.


## How to Report Issues and Contribute Fixes

To report a bug or request a feature, open a GitLab issue. If you have a fix or
implementation, open a merge request linked to that issue (`Resolves: #NNN` in the
commit message).

Do not attach patches to issues. Merge requests keep CI and commit authorship with
the contributor, where they belong — review is the project's responsibility once an
MR is open.

Patches attached to issues will be closed with a request to open an MR instead.

The MR does not need to be perfect on the first submission. Maintainers will review
it, leave feedback, and approve once it meets the bar.


## Git commits:

Note that when contributing code you will need to assert that the contribution is
in accordance to the "Developer's Certificate of Origin" as found in the
file [DCO.txt](doc/DCO.txt).

To indicate that, make sure that your contributions (merge requests),
contain a "Signed-off-by" line, with your real name and e-mail address.
To automate the process use "git am -s" to produce patches and/or set the
a template to simplify this process, as follows.

```
$ echo "Signed-off-by: My Full Name <email@example.com>" > ~/.git-template
$ git config commit.template ~/.git-template
```


## Test suite:

   New functionality should be accompanied by a test case which verifies
the correctness of ocserv operation on successful use of the new
functionality, as well as on fail cases. The test suite is run on "make check"
on every system ocserv is installed, except for the tests/suite part
which is only run during development.

 ocserv relies on gitlab-ci which is configured in .gitlab-ci.yml
file in the repository. The goal is to have a test suite which runs for
every new merge request prior to merging. There are no particular rules for
the test targets, except for them being reliable and running in a reasonable
time frame (~1 hour).

Tests must be **self-diagnosing**: a failure must be understandable from CI
log output alone, without requiring local reproduction. Shell tests must print
what they were testing and why it failed (e.g. `echo "FAIL: expected X, got Y"`).
C unit tests must print the failing condition and relevant values before
returning non-zero. Silent tests that fail with only an exit code will not be accepted.


## Reviewing code

 Reviews are necessary for external contributions, and encouraged otherwise. A review,
is a way to prevent accidental mistakes, or design issues, as well as enforce this guide.
For example, verify that there is a reasonable test suite, and whether it covers
reasonably the new code, as well as check for obvious mistakes in the new code.

The intention is to keep reviews lightweight, and rely on CI for tasks such
as compiling and testing code and features.

[Guidelines to consider when reviewing.](https://github.com/thoughtbot/guides/tree/master/code-review)


## Before opening a merge request

No review will begin before CI passes.

- [ ] CI passes
- [ ] Every changed line is relevant to the change — no drive-by refactoring
- [ ] `ninja -C build` succeeds after each commit, not just at the final set
- [ ] Every commit has `Signed-off-by: Your Name <email@example.com>`
- [ ] Both a positive test (correct behavior) and a negative test (bad input rejected)
- [ ] Tests are self-diagnosing: a CI failure is explainable from the log output alone
- [ ] No new Linux-specific syscalls without `#ifdef __linux__` guard


## CCAN

The directory `src/ccan` contains libraries from the
[CCAN project](https://github.com/rustyrussell/ccan).
When considering a helper module, check CCAN first.


## AI Assistance Policy

AI tool use is assumed and does not require disclosure. What matters is human
accountability: every line you submit is your responsibility, regardless of how
it was generated. Reviewers will hold you accountable as the author.

**If you use AI assistance:**

- Follow the guidance in [`AGENTS.md`](AGENTS.md) for all AI-assisted work.
- External contributors should load the `ocserv-contributor` persona
  (`contrib/ai/personas/ocserv-contributor.md`) before starting.
- Maintainers doing AI-assisted review or development should load the
  `ocserv-core-dev` persona (`contrib/ai/personas/ocserv-core-dev.md`).

**Review calibration:** Reviewers may ask how a contribution was developed if it
raises quality questions. Be prepared to explain your approach. Submissions that
show signs of unchecked generation — hallucinated API calls, missing tests, style
inconsistencies — may be returned with a request for additional work rather than
an inline review.

**Not acceptable:** Submitting code you cannot explain or defend. Own your patch.


# Coding style

## C dialect:

  All code in ocserv is expected to conform to C99.


## Indentation style:

 In general, use [the Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html).
You may indent the source using GNU indent, e.g. "indent -linux *.c".


## Commenting style

In general for documenting new code we prefer self-documented code to comments. That is:
  - Meaningful function and macro names
  - Short functions which do a single thing

That does not mean that no comments are allowed, but that when they are
used, they are used to document something that is not obvious, or the protocol
expectations.


## Header guards

  Each private C header file SHOULD have a header guard consisting of the
project name and the file path relative to the project directory, all uppercase.

Example: `src/main.h` uses the header guard `MAIN_H`.

The header guard is used as first and last effective code in a header file,
like e.g. in src/main.h:

```
#ifndef MAIN_H
#define MAIN_H

...

#endif /* MAIN_H */
```
