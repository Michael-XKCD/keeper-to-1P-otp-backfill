"""Put the 2FA seeds back on the 1Password items the Keeper import dropped.

1Password's Keeper importer reads TOTP only from Keeper's native one-time
password field, so seeds sitting anywhere else never came across. Converting the
Keeper records so a re-import picks them up works only for a person's *private*
records: shared Keeper folders were migrated into shared 1Password vaults by a
separate one-time pass that does not run again, so a converted record in a
shared folder has no path into 1Password at all.

So this writes to 1Password directly. It reads Keeper for the seeds, matches
each record to the item it became, and adds a one-time-password field to items
that have none. It is dry-run by default; it never deletes, never edits a field
it did not create, and never touches an item that already has a code.

Section 1 holds the secret-containment rules, section 6 the matching guard, and
section 7 the two rules that keep a seed out of argv and off disk.
"""

import argparse
import getpass
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import unicodedata
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Callable

__version__ = "0.8.0"

# 1. Secret containment and log redaction
#
# No seed, otpauth:// URI or generated code may reach a log record, stdout or
# disk. ``Secret`` is the contract; ``scrub`` and the logging filter over it
# rewrite residual secret material in formatted text, the net under it.

PLACEHOLDER = "<redacted>"

# Most-specific first, so a whole otpauth URI is replaced before the narrower
# secret=/base32 rules can leave the rest of it intact.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # A whole otpauth:// or otpauth-migration:// URI. The scheme survives so a
    # log line says what was removed; the lookahead keeps scrubbing idempotent,
    # since re-scrubbing an already scrubbed line would otherwise append a
    # second placeholder and fail every "has this been cleaned?" check.
    (re.compile(r"otpauth(?:-migration)?://(?!" + re.escape(PLACEHOLDER) + r")"
                r"[^\s'\"<>)\]]+", re.IGNORECASE),
     f"otpauth://{PLACEHOLDER}"),
    # A secret=/seed=/data= query parameter anywhere else.
    (re.compile(r"\b(secret|seed|data)=([^&\s'\"<>)\]]+)", re.IGNORECASE),
     rf"\1={PLACEHOLDER}"),
    # A bare base32 seed, in two rules because case matters. All-caps goes
    # outright; mixed or lower case must also hold a 2-7 digit, which real seeds
    # essentially always do and English words never do, so a lowercase seed is
    # caught without eating every long lowercase title. Not hypothetical: this
    # tool never canonicalizes, so a seed enrolled lowercase travels lowercase.
    # A seed written in groups, which is how Google, AWS and Keeper all *show*
    # one, so a seed typed or pasted into a Keeper custom field by hand very
    # often arrives spaced or hyphenated. Four groups minimum, so ordinary prose
    # cannot reach it.
    (re.compile(r"\b[A-Za-z2-7]{4}(?:[ -][A-Za-z2-7]{4}){3,}\b"), PLACEHOLDER),
    (re.compile(r"\b[A-Z2-7]{16,}={0,6}\b"), PLACEHOLDER),
    (re.compile(r"\b(?=[A-Za-z2-7]*[2-7])[A-Za-z2-7]{16,}={0,6}\b"), PLACEHOLDER),
    # A hex-encoded seed. 32 characters is a 128-bit key, not an item title.
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), PLACEHOLDER),
    # A standalone 6-digit token: a generated TOTP code. Over-redaction is
    # harmless here, since these lines carry status, not data.
    #
    # Deliberately not widened to 7 or 8 digits, and deliberately no rule for a
    # lowercase seed carrying no 2-7 digit. Both were proposed in review and
    # rejected: scrub is the net *under* Secret, not the primary defence, and no
    # code path here ever emits a generated code - `generates_a_code` returns a
    # bool. \d{6,8} would redact a bare date like 20260825 out of every report,
    # and a no-digit rule long enough to spare "administration" (26+) still
    # reaches only seeds of 26 characters or more, while eating
    # "antidisestablishmentarianism" on the way.
    (re.compile(r"(?<![\w.-])\d{6}(?![\w.-])"), PLACEHOLDER),
)


class SecretLeakError(RuntimeError):
    """Raised when a :class:`Secret` is asked to serialize itself."""


class Secret:
    """An in-memory string that renders as ``<redacted>`` everywhere."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"Secret takes a str, got {type(value).__name__}")
        self._value = value

    def reveal(self) -> str:
        """The underlying value; call sites must not log it. Prefer a predicate."""
        return self._value

    # -- predicates: questions a caller can ask *about* a secret without
    # receiving it. Each returns a bool, so only that one bit escapes.

    def is_blank(self) -> bool:
        """True if the value is empty or only whitespace."""
        return not self._value.strip()

    def startswith(self, prefix: str, *, casefold: bool = True) -> bool:
        """Spot an ``otpauth`` URI scheme without reading the URI."""
        head = self._value[:len(prefix)]
        if casefold:
            return head.casefold() == prefix.casefold()
        return head == prefix

    def __repr__(self) -> str:
        return PLACEHOLDER

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return PLACEHOLDER

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            # Encoded bytes, not str: compare_digest raises TypeError on
            # non-ASCII, and a real vault can hold an OTP URI with a raw UTF-8
            # issuer label. Raising would end a whole run over one accent.
            return hmac.compare_digest(self._value.encode("utf-8"),
                                       other._value.encode("utf-8"))
        return NotImplemented

    # Secrets must not become dict keys or land in sets.
    __hash__ = None  # type: ignore[assignment]

    def __getstate__(self) -> object:
        raise SecretLeakError("Secret must not be pickled or copied to disk")

    def __reduce__(self) -> object:
        raise SecretLeakError("Secret must not be pickled or copied to disk")


def scrub(text: str) -> str:
    """Replace anything that looks like secret material in ``text``."""
    if not text:
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def contains_secret_material(text: str) -> bool:
    """True if ``text`` still carries something :func:`scrub` would remove."""
    return scrub(text) != text


class RedactingFilter(logging.Filter):
    """Scrub a record before any handler formats it. Interpolates first: a
    format string like ``"data=%s"`` holds a substring this module rewrites, so
    scrubbing it destroys the ``%s`` and the record fails to format at emit.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            # Malformed args must not make a logging call raise inside the tool.
            message = str(record.msg)
        record.msg = scrub(message)
        record.args = None
        return True


class RedactingFormatter(logging.Formatter):
    """Scrub the fully formatted line, tracebacks and all."""

    def format(self, record: logging.LogRecord) -> str:
        return scrub(super().format(record))


# 2. Logging configuration
#
# Every handler installed here carries both redaction layers; logs go to stderr
# so stdout stays reserved for the summary. There is deliberately no file
# handler - nothing belongs on disk but the JSON summary the user asks for.

LOGGER_NAME = "otp_backfill"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the tool's logger (``otp_backfill`` or a named child of it)."""
    return logging.getLogger(LOGGER_NAME if name is None else f"{LOGGER_NAME}.{name}")


def configure_logging(*, verbose: bool = False, stream=None) -> logging.Logger:
    """Install a single redacting stderr handler on the tool's logger."""
    logger = get_logger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Own the handler list: re-running configuration must not stack handlers.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(RedactingFormatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    # Never hand records to root, whose handlers we cannot guarantee redact.
    logger.propagate = False

    _protect_root(stream)
    return logger


def _protect_root(stream=None) -> None:
    """Put a redacting handler on the root logger too: ``keepercommander`` logs
    to **root**, and with no handler there Python's ``lastResort`` writes to
    stderr unfiltered. The filter must go on the *handler*, since a logger's own
    filters skip records propagated up from children.
    """
    root = logging.getLogger()
    for existing in root.handlers:
        if getattr(existing, "_otp_backfill_redacting", False):
            return

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setLevel(logging.WARNING)
    handler.setFormatter(RedactingFormatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    handler._otp_backfill_redacting = True  # type: ignore[attr-defined]
    root.addHandler(handler)


log = get_logger("engine")
logger = get_logger("keeper")
op_logger = get_logger("1password")

# 3. The Keeper-side domain types
#
# Anything possibly secret is a ``Secret``, so a stray repr() cannot leak it.
# Everything else is plain text, which is what lets the summary be useful.


class RecordType(str, Enum):
    """Keeper record type. The sole predictor of whether OTP migrated."""

    LOGIN = "login"
    GENERAL = "general"
    OTHER = "other"

    @classmethod
    def parse(cls, raw: str | None) -> "RecordType":
        text = (raw or "").strip().casefold()
        if text in ("login", "logins"):
            return cls.LOGIN
        if text in ("general", "", "legacy", "classic"):
            # Legacy/classic records have no typed schema and behave like
            # General ones: any TOTP lives in a custom field.
            return cls.GENERAL
        return cls.OTHER


@dataclass(frozen=True)
class KeeperField:
    """One field on a record. Type and label print; the value does not."""

    #: Keeper's v3 type name: login, password, url, oneTimeCode, text, ...
    field_type: str
    #: Display label. Empty for a typed field that carries no custom label.
    label: str
    value: Secret


@dataclass(frozen=True)
class KeeperRecord:
    """A Keeper vault record, normalized away from the SDK's shape."""

    uid: str
    title: str
    record_type: RecordType = RecordType.GENERAL
    #: Names of the Keeper **shared folders** holding this record, which is what
    #: the migration turned into 1Password vaults. Not the subfolder it sits in:
    #: a record in "Engineering > AWS" became an item in the *Engineering* vault, so
    #: the subfolder name corroborates nothing. Empty for a private record.
    folders: tuple[str, ...] = ()
    #: **Every** field on the record, in order, whatever it is.
    #:
    #: One list rather than a fixed schema of username/password/url/otp.
    #: Converting must produce a *duplicate*, and a record can carry anything: a
    #: seed beside an API key beside three URLs beside a field someone named
    #: after a person. Named slots silently drop whatever has no slot, so the
    #: whole list is kept and the writer replays what was actually there.
    fields: tuple[KeeperField, ...] = ()
    last_modified: str | None = None

    def first(self, *field_types: str) -> Secret | None:
        """The first value whose type matches, for the few callers that care."""
        wanted = {f.casefold() for f in field_types}
        return next((f.value for f in self.fields
                     if f.field_type.casefold() in wanted), None)

    # -- derived views ----------------------------------------------------
    #
    # Convenience over the one list, never storage. The distinction is the whole
    # point: these name the fields a reader usually wants, while `fields` still
    # holds everything, so a field nothing here names is carried anyway.

    @property
    def username(self) -> str:
        return _unwrap(self.first(*LOGIN_FIELD_TYPES))





#: Keeper's native one-time-code field type on a v3 typed record, and the name
#: the reader recognises it by. Reading only: nothing here writes to Keeper.
NATIVE_OTP_FIELD_TYPE = "oneTimeCode"


# 4. Finding *which* field holds the 2FA seed, without looking at what it says
#
# A copy does not require understanding what is copied, so nothing here parses,
# validates, decodes or generates, and the tool never has to know whether Keeper
# stores a full otpauth:// URI or a bare base32 seed. Evidence used, all cheap:
# the vault typing the field oneTimeCode/totp; the field's label; and last the
# value starting with the otpauth scheme - the only place the value is touched,
# unavoidably, since a seed stored under a label like "Notes" is real and
# nothing else would find it.

#: Keeper field types meaning "this is a one-time code", from the vault's own
#: schema (``RecordField('oneTimeCode', 'otp', Multiple.Never)``, plus v2's
#: ``totp``). Shared by the seed search and the read adapter; separate copies
#: once disagreed and a custom field typed ``otp`` was missed by the reader.
NATIVE_OTP_FIELD_TYPES = frozenset({"onetimecode", "one_time_code", "totp", "otp"})

#: Not a real label; a report marker for a seed taken from the native field.
NATIVE_SOURCE = "(native)"

#: The scheme a self-describing OTP value begins with.
OTPAUTH_SCHEME = "otpauth"


@dataclass(frozen=True)
class SeedField:
    """One field holding a seed. ``label`` prints; ``value`` stays wrapped."""

    label: str
    value: Secret
    #: The vault typed this field as the OTP field, rather than us inferring it
    #: from a label or scheme prefix, which makes it authoritative. See
    #: :meth:`SeedSearch.has_conflict`.
    is_native: bool = False


@dataclass(frozen=True)
class SeedSearch:
    """What a record turned out to hold."""

    fields: tuple[SeedField, ...] = ()

    @property
    def native(self) -> SeedField | None:
        return next((f for f in self.fields if f.is_native), None)

    @property
    def has_conflict(self) -> bool:
        """Two *custom* fields whose values are not byte-identical. A native
        field never conflicts - Keeper typed it, so a custom field beside it is
        a leftover - which sidesteps what opaque comparison cannot see:
        ``otpauth://...?secret=ABC`` and a bare ``ABC`` are one seed in two
        formats, and telling them apart would mean parsing.
        """
        if self.native is not None:
            # Keeper typed one of these itself, so the others are leftovers and
            # there is nothing to be in conflict about. Said in the docstring
            # above; enforced here so the caller cannot see a "conflict" it was
            # promised could not happen.
            return False
        custom = [f for f in self.fields if not f.is_native]
        if len(custom) < 2:
            return False
        first = custom[0].value
        return any(f.value != first for f in custom[1:])

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(f.label for f in self.fields)


def find_seed_fields(record: KeeperRecord) -> SeedSearch:
    """Identify every field on ``record`` that holds a seed. Never raises.

    One walk over one list: a natively typed field is just a field whose type
    Keeper set, so there is no separate native slot to check first.
    """
    found: list[SeedField] = []

    for field in record.fields:
        label = field.label or _fallback_label(field.field_type) or "(unlabeled)"
        field_type = (field.field_type or "").replace("_", "").casefold()

        # Strongest: the vault types the field itself. The value stays closed.
        if field_type in NATIVE_OTP_FIELD_TYPES:
            if _has_content(field.value):
                found.append(SeedField(label, field.value, is_native=True))
            continue

        # Next: the label says so. Still no look at the value.
        if label_suggests_otp(label):
            if _has_content(field.value):
                found.append(SeedField(label, field.value))
            continue

        # Last resort, and the only value-touching test.
        if _starts_with_otpauth(field.value):
            found.append(SeedField(label, field.value))

    return SeedSearch(fields=tuple(found))


def _has_content(value: Secret) -> bool:
    """Is there anything in this field? Asked of the Secret, not of the value."""
    return not value.is_blank()


def _starts_with_otpauth(value: Secret) -> bool:
    """Answered inside the wrapper, so a seed never lands in a local."""
    return value.startswith(OTPAUTH_SCHEME)


# -- Which labels mean "2FA seed" ---------------------------------------------

#: Labels that mean the field is *meant* to be a 2FA seed.
OTP_LABEL_STRONG_HINTS = (
    "otpauth",
    "totp",
    "hotp",
    "otp",
    "2fa",
    "two factor",
    "twofactor",
    "mfa",
    "authenticator",
    "one time password",
    "onetime password",
    "one time code",
    "2 step",
    "two step",
)

#: Labels carrying an OTP hint that are known *not* to hold a seed. Checked
#: first, so "2FA backup codes" is never treated as one.
OTP_LABEL_ANTI_HINTS = (
    "backup code",
    "recovery code",
    "scratch code",
    "backup key",
    "phone",
    "sms",
    "note",
    # Credentials seen in the wild that are emphatically not TOTP seeds.
    "access key",
    "api key",
    "api secret",
    "client secret",
    "ssh key",
    "private key",
    "public key",
    "license key",
    "product key",
    "serial",
)

_PUNCT_RE = re.compile(r"[^a-z0-9]+")


def normalize_label(label: str) -> str:
    """Lowercase a field label and collapse punctuation to single spaces."""
    return _PUNCT_RE.sub(" ", label.casefold()).strip()


def label_suggests_otp(label: str) -> bool:
    """True if a field's label says it holds a one-time password. Anti-hints
    win, and labels that merely *could* be one - "Secret Key", "API Key" - are
    deliberately absent, because they are far more often some other credential
    - a 1Password account Secret Key, a reCAPTCHA secret - and this tool has no
    business opening a credential it was not asked to migrate.
    """
    normalized = normalize_label(label)
    if not normalized:
        return False
    if any(anti in normalized for anti in OTP_LABEL_ANTI_HINTS):
        return False
    return any(hint in normalized for hint in OTP_LABEL_STRONG_HINTS)

# 5. The Keeper adapter - the only place the vendor SDK exists
#
# Read only. Auth is **SSO -> session token**: no master password is ever
# collected, and close() destroys the session and any cached device token on the
# way out, including after a failure.
#
# This tool does not write to Keeper at all, so the SDK handle is narrowed to
# the three calls it actually needs. `api.delete_record` and the whole of
# `record_management` are simply not reachable through it.
#
# The SDK is optional and absent from the build machine, so it is imported
# *lazily inside methods* and a missing one raises KeeperAuthError naming the
# extra, never an ImportError at import time. Every SDK-object rule is a pure
# module-level function over duck-typed objects, which is why they are testable
# with no SDK and no session, and why one malformed record cannot abort a read.


class KeeperAuthError(RuntimeError):
    """Login failed, or the SDK is not installed on this machine."""


class KeeperReadError(RuntimeError):
    """The vault could not be read after a successful login."""


#: The only ``keepercommander.api`` functions this tool may reach.
#:
#: ``api.delete_record`` exists. Nothing here calls it, and nothing here should
#: ever be able to: the whole safety argument is that converting is additive and
#: the original record is the backup. Holding the bare module left deletion one
#: attribute lookup away from a future edit or a stray line, so the handle is
#: narrowed to what is actually used and everything else raises.
_ALLOWED_API_CALLS = frozenset({"login", "sync_down", "communicate_rest"})
def _restricted(wrapped: Any, allowed: frozenset[str], what: str,
                endpoints: frozenset[str] | None = None) -> Any:
    """An SDK module with only an allowlist of callables reachable.

    A closure, not an object with the module on a slot. An earlier version kept
    it in ``__slots__``, which meant ``api._wrapped.delete_record`` reached the
    unrestricted module in a single attribute lookup: ``__getattr__`` only runs
    when *normal* lookup fails, so the slot was never protected by it. Nothing
    in this file did that, but "cannot" has to mean cannot.

    ``communicate_rest`` is on the allowlist because logging out needs it, and
    it is a general authenticated REST call: with a different endpoint it writes
    to Keeper. So it is wrapped again, and only ``endpoints`` may be reached.
    """

    class _Restricted:
        __slots__ = ()

        def __getattr__(self, name: str) -> Any:
            if name not in allowed:
                raise AttributeError(
                    f"{what}.{name} is not reachable from this tool. It calls "
                    f"only {', '.join(sorted(allowed))}, and it never writes to "
                    "or deletes from Keeper."
                )
            attribute = getattr(wrapped, name)
            if name == "communicate_rest" and endpoints is not None:
                def _only_allowed_endpoints(params, request, endpoint,
                                            *args, **kwargs):
                    if endpoint not in endpoints:
                        raise AttributeError(
                            f"{what}.communicate_rest may only reach "
                            f"{', '.join(sorted(endpoints))}, not {endpoint!r}."
                        )
                    return attribute(params, request, endpoint, *args, **kwargs)
                return _only_allowed_endpoints
            return attribute

    return _Restricted()


# -- The one place a Secret is opened -----------------------------------------
def _unwrap(value: Secret | str | None) -> str:
    """Open a :class:`Secret`. The only unwrap in the whole file.

    Two call sites: :attr:`KeeperRecord.username`, which needs plain text to
    match on, and :meth:`OnePasswordCli.add_otp`, which puts the seed straight
    into the payload that goes to `op` on stdin. A test counts them, so a third
    is a deliberate act rather than an accident.
    """
    if value is None:
        return ""
    if isinstance(value, Secret):
        return value.reveal()
    if isinstance(value, str):
        return value
    # Anything else would be repr()'d into a Keeper field: silent corruption,
    # and for the seed it destroys what the tool is here to move.
    raise TypeError(
        f"expected a Secret or str for a field value, got {type(value).__name__}"
    )


# -- Duck-typing helpers. None of these raise; that is their entire job. -------
def _attr(obj: Any, *names: str) -> Any:
    """First non-``None`` of ``names``, read as a key or an attribute."""
    for name in names:
        try:
            value = obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)
        except Exception:  # a property or a .get() that raises is a missing value
            value = None
        if value is not None:
            return value
    return None


def _as_sequence(raw: Any) -> list[Any]:
    """Coerce a fields/custom container into a list, whatever it is."""
    if raw is None:
        return []
    if isinstance(raw, Mapping):
        return list(raw.values())
    if isinstance(raw, (str, bytes, bytearray)):
        return [raw]
    try:
        return list(raw)
    except TypeError:
        return [raw]


def _value_list(raw: Any) -> list[Any]:
    """Normalize a field value into a list, as ``TypedField.__init__`` does."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set, frozenset)):
        return list(raw)
    return [raw]


def _iter_fields(obj: Any, name: str) -> list[Any]:
    return _as_sequence(_attr(obj, name))


def _field_type(field_obj: Any) -> str:
    return _text(_attr(field_obj, "type", "field_type", "$ref")).casefold()


def _field_label(field_obj: Any) -> str:
    # Typed fields label with ``label``; legacy custom dicts use ``name``.
    return _text(_attr(field_obj, "label", "name"))


def _load_sdk_record(vault: Any, params: Any, uid: str) -> Any:
    """Load one record from the synced cache as its SDK class, or ``None``.

    ``KeeperRecord.load`` *returns None* rather than raising for an uncached uid
    or an unsupported version, and hands back a PasswordRecord for v2 and a
    TypedRecord for v3/v6 - which is why both conversion paths exist. Loading
    rather than rebuilding also matters on the write side: a v2 record
    round-tripped this way keeps the ``totp`` in its ``extra`` blob.
    """
    loader = getattr(getattr(vault, "KeeperRecord", None), "load", None)
    if not callable(loader):
        return None
    try:
        return loader(params, uid)
    except Exception:
        # The uid is an identifier, not secret material; the SDK's message is
        # not repeated.
        logger.debug("Could not load Keeper record %s through the SDK", uid)
        return None


def _text(value: Any) -> str:
    """Render any value as a string without ever raising. A :class:`Secret` is
    the one thing it refuses: writing the literal ``<redacted>`` into a Keeper
    field would destroy the value this tool exists to preserve, and unwrapping
    belongs at :func:`_unwrap` and nowhere else.
    """
    if isinstance(value, Secret):
        raise TypeError(
            "a Secret reached the plain-text renderer; unwrap it at the SDK "
            "boundary instead"
        )
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    try:
        return str(value)
    except Exception:  # a __str__ that raises must not take the run down
        return ""


def _text_or_none(value: Any) -> str | None:
    text = _text(value)
    return text or None


def _safe_setattr(obj: Any, name: str, value: Any) -> None:
    try:
        setattr(obj, name, value)
    except Exception:
        # Read-only property or __slots__ without the attribute. Nothing to do.
        pass


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


# -- Pure conversion: SDK object -> KeeperRecord -------------------------------

#: The REST endpoint that revokes a session token server-side, which is what
#: Commander's own ``logout`` calls before clearing params locally.
LOGOUT_ENDPOINT = "vault/logout_v3"

#: Field types that identify the account.
LOGIN_FIELD_TYPES = frozenset({"login", "username", "email"})

#: Field types that hold a site address.
URL_FIELD_TYPES = frozenset({"url", "link", "website"})

#: The password slot. Carried like any other credential so the converted record
#: is a full copy rather than a stub holding only the OTP.
PASSWORD_FIELD_TYPES = frozenset({"password", "secret"})

#: Free-text notes. Read to classify a field's type, never carried.
NOTES_FIELD_TYPES = frozenset({"note", "notes", "multiline"})

#: Field types with nothing text-like in them. Their values are file UIDs.
SKIP_FIELD_TYPES = frozenset({"fileref", "file_ref"})

#: Legacy ``record_cache`` / ``PasswordRecord`` keys, in precedence order.
#: ``secret1`` is the v2 wire name for the login; ``link`` is the v2 URL.
_LEGACY_UID_KEYS = ("record_uid", "recordUid", "uid")
_LEGACY_TITLE_KEYS = ("title", "name")
_LEGACY_LOGIN_KEYS = ("login", "secret1", "username", "user", "email")
_LEGACY_URL_KEYS = ("url", "link", "website")
_LEGACY_PASSWORD_KEYS = ("password", "secret2")
_LEGACY_NOTES_KEYS = ("notes", "note")
_LEGACY_OTP_KEYS = ("totp", "totp_url", "one_time_code", "oneTimeCode", "otp")
_LEGACY_TYPE_KEYS = ("record_type", "type", "$type", "type_name")
_LEGACY_CUSTOM_KEYS = ("custom", "custom_fields", "customFields", "fields")
_LEGACY_MODIFIED_KEYS = ("client_modified_time", "last_modified", "client_time_modified")

#: Params attributes wiped on close. Tokens and keys become ``None``; caches
#: become empty containers so a later attribute read does not explode.
#: ``clear_session()`` covers most of them; this is the pass for when it is
#: absent or raised.
_SESSION_ATTRS = (
    "session_token",
    "session_token_bytes",
    "auth_verifier",
    "data_key",
    "client_key",
    "rsa_key",
    "rsa_key2",
    "ecc_key",
    "salt",
    "password",
    "clone_code",
    "device_private_key",
    "device_token",
    "account_uid_bytes",
    "sync_down_token",
    "sso_login_info",
    "msp_tree_key",
)
_CACHE_ATTRS = (
    "record_cache",
    "record_type_cache",
    "non_shared_data_cache",
    "subfolder_cache",
    "subfolder_record_cache",
    "folder_cache",
    "shared_folder_cache",
    "team_cache",
    "meta_data_cache",
    "key_cache",
    "record_history",
)


def to_keeper_record(obj: Any, folders: "tuple[str, ...]" = ()) -> KeeperRecord:
    """Convert an SDK object into a :class:`KeeperRecord`, dispatching on shape.

    The test is ``fields``, which only ``TypedRecord`` has; testing ``custom``
    would be wrong, since *both* classes have it and routing a
    ``PasswordRecord`` through the typed reader drops its ``totp`` and ``login``.
    """
    if isinstance(obj, Mapping):
        data = record_data_from_cache_entry(obj)
        if _attr(data, "fields") is not None:
            return record_from_typed(data, folders)
        return record_from_legacy(data, folders)
    if _attr(obj, "fields") is not None:
        return record_from_typed(obj, folders)
    if _attr(obj, "login", "totp", "link", "custom", "custom_fields") is not None:
        return record_from_legacy(obj, folders)
    return record_from_typed(obj, folders)


def record_data_from_cache_entry(entry: Any) -> Any:
    """Unwrap a raw ``params.record_cache`` entry into the record's data body.

    Its only record content is the still-JSON ``data_unencrypted`` /
    ``extra_unencrypted``, and a v2 one-time code lives in the latter rather
    than the data body, so it is folded in here.
    """
    if not isinstance(entry, Mapping):
        return entry
    data = _decode_json_object(entry.get("data_unencrypted"))
    if data is None:
        return entry

    merged = dict(data)
    for key in ("record_uid", "client_modified_time"):
        if entry.get(key) is not None:
            merged.setdefault(key, entry.get(key))
    if entry.get("version") == 2:
        # A v2 record has no type string; Commander reports it as 'general'.
        merged.setdefault("type", "general")
        totp = _legacy_totp_from_extra(entry.get("extra_unencrypted"))
        if totp:
            merged.setdefault("totp", totp)
    return merged


def _decode_json_object(raw: Any) -> dict[str, Any] | None:
    """Parse a JSON object out of ``str``/``bytes``, or ``None`` if it is not one."""
    if isinstance(raw, Mapping):
        return dict(raw)
    if not isinstance(raw, (str, bytes, bytearray)):
        return None
    try:
        decoded = json.loads(raw)
    except Exception:  # corrupted record data must not take the run down
        return None
    return decoded if isinstance(decoded, dict) else None


def _legacy_totp_from_extra(raw: Any) -> str:
    """The v2 one-time code out of a record's ``extra`` blob, or ``""``."""
    extra = _decode_json_object(raw)
    if extra is None:
        return ""
    fields = extra.get("fields")
    if not isinstance(fields, list):
        return ""
    for entry in fields:
        if isinstance(entry, Mapping) and entry.get("field_type") == "totp":
            return _text(entry.get("data"))
    return ""


def record_from_typed(obj: Any, folders: "tuple[str, ...]" = ()) -> KeeperRecord:
    """Convert a modern typed record. Both containers are walked, since a
    ``oneTimeCode`` field is valid in either, and every field is kept with the
    type Keeper gave it: the converted record has to be a duplicate, so nothing
    is routed into a named slot and nothing is dropped. Every attribute is
    optional and nothing may raise - one malformed record must not abort a read.
    """
    fields: list[KeeperField] = []
    for field_obj in [*_iter_fields(obj, "fields"), *_iter_fields(obj, "custom")]:
        field_type = _field_type(field_obj)
        if field_type in SKIP_FIELD_TYPES:
            continue
        label = _field_label(field_obj)
        fields.extend(
            KeeperField(field_type or "text", label, Secret(value))
            for value in _field_values(field_obj)
        )

    return KeeperRecord(
        uid=_text(_attr(obj, *_LEGACY_UID_KEYS)),
        title=_text(_attr(obj, *_LEGACY_TITLE_KEYS)),
        record_type=RecordType.parse(_text_or_none(_attr(obj, *_LEGACY_TYPE_KEYS))),
        folders=tuple(folders or ()),
        fields=tuple(fields),
        last_modified=_text_or_none(_attr(obj, *_LEGACY_MODIFIED_KEYS)),
    )


def record_from_legacy(data: Any, folders: "tuple[str, ...]" = ()) -> KeeperRecord:
    """Convert a decoded v2 record body or a ``PasswordRecord``.

    A v2 record keeps its credentials as named attributes rather than a field
    list, so they are lifted into fields carrying the v3 type name Keeper would
    use - ``link`` becomes ``url``, ``totp`` becomes ``oneTimeCode`` - which is
    what lets the writer replay a v2 record onto a v3 one without a second
    translation step. Custom entries label under ``name``.
    """
    fields: list[KeeperField] = []

    # The v2 named slots, in the order Keeper shows them.
    for keys, field_type in ((_LEGACY_LOGIN_KEYS, "login"),
                             (_LEGACY_PASSWORD_KEYS, "password"),
                             (_LEGACY_URL_KEYS, "url"),
                             (_LEGACY_OTP_KEYS, NATIVE_OTP_FIELD_TYPE)):
        # Deduped per slot: `url` and `link` are the same field under two names,
        # so a record carrying both would otherwise yield the value twice.
        for value in _dedupe(_coerce_values(_attr(data, *keys))):
            fields.append(KeeperField(field_type, "", Secret(value)))

    for entry in _as_sequence(_attr(data, *_LEGACY_CUSTOM_KEYS)):
        if isinstance(entry, (str, bytes, bytearray)):
            # A bare string custom entry has no label. Keep the value.
            fields.extend(KeeperField("text", "", Secret(value))
                          for value in _coerce_values(entry))
            continue
        field_type = _field_type(entry)
        if field_type in SKIP_FIELD_TYPES:
            continue
        label = _field_label(entry) or _fallback_label(field_type)
        fields.extend(
            KeeperField(field_type or "text", label, Secret(value))
            for value in _field_values(entry)
        )

    return KeeperRecord(
        uid=_text(_attr(data, *_LEGACY_UID_KEYS)),
        title=_text(_attr(data, *_LEGACY_TITLE_KEYS)),
        record_type=RecordType.parse(_text_or_none(_attr(data, *_LEGACY_TYPE_KEYS))),
        folders=tuple(folders or ()),
        fields=tuple(fields),
        last_modified=_text_or_none(_attr(data, *_LEGACY_MODIFIED_KEYS)),
    )


def _fallback_label(field_type: str) -> str:
    """Name an unlabeled field after its type, unless the type says nothing."""
    return "" if field_type in ("", "text") else field_type


def _field_values(field_obj: Any) -> list[str]:
    return _coerce_values(_attr(field_obj, "value", "values"))


def _coerce_values(raw: Any) -> list[str]:
    """A field value as a list of non-blank strings, whatever shape it arrived in."""
    return [text for text in (_text(item) for item in _value_list(raw)) if text.strip()]


def _first_value(raw: Any) -> str:
    values = _coerce_values(raw)
    return values[0] if values else ""


def shared_folders_index(params: Any) -> dict[str, tuple[str, ...]]:
    """Map record uid -> the shared folders holding it.

    Read from ``shared_folder_cache`` rather than walking the folder tree,
    because that cache is keyed by the *shared* folder - the thing the migration
    turned into a 1Password vault. The folder tree would give the subfolder a
    record sits in ("AWS"), which corresponds to no vault.

    Reporting and corroboration metadata only, so a cache that is missing or a
    shape that surprises us yields a thinner index rather than an error: the
    guard treats absent evidence as no corroboration, which refuses.
    """
    index: dict[str, set[str]] = {}
    cache = _attr(params, "shared_folder_cache")
    if not isinstance(cache, Mapping):
        return {}

    for shared_folder in cache.values():
        if not isinstance(shared_folder, Mapping):
            continue
        name = _text(shared_folder.get("name_unencrypted"))
        if not name:
            continue
        records = shared_folder.get("records")
        try:
            entries = list(records or ())
        except TypeError:  # not iterable; nothing to index
            continue
        for entry in entries:
            uid = _text(entry.get("record_uid")) if isinstance(entry, Mapping) \
                else _text(entry)
            if uid:
                index.setdefault(uid, set()).add(name)
    return {uid: tuple(sorted(names)) for uid, names in index.items()}


# -- Login UI -----------------------------------------------------------------
def sso_only_login_ui(console_ui: Any) -> Any:
    """A Commander ``LoginUi`` that can finish SSO but can never take a password.

    Overrides one method of the console UI: the password prompt, cancelled
    instead of asked. Fail-closed - ``LoginV3Flow`` then returns with no
    ``params.session_token``, which :meth:`authenticate` treats as an error.
    """

    class SsoOnlyLoginUi(console_ui.ConsoleLoginUi):  # type: ignore[misc, name-defined]
        def on_password(self, step: Any) -> None:
            logger.warning(
                "Keeper asked for a master password. This tool is SSO-only, so "
                "the login was cancelled instead."
            )
            step.cancel()

    return SsoOnlyLoginUi()


# -- The read adapter ---------------------------------------------------------
class CommanderKeeperReader:
    """Reads the vault through ``keepercommander``, SSO only. ``close()`` is
    safe at any point, twice or after a failed login: the CLI calls it from a
    ``finally``.
    """

    def __init__(self, username: str, server: str | None = None) -> None:
        if not username or not username.strip():
            raise KeeperAuthError("a Keeper username (email) is required for SSO login")
        self._username = username.strip()
        self._server = (server or "").strip() or None
        self._params: Any = None
        self._api: Any = None
        self._vault: Any = None
        self._synced = False

    def authenticate(self) -> None:
        """Log in through SSO; never prompts for a password. Interactive at the
        terminal, not a browser handshake: Commander prints the SSO URL and
        waits for the token to be pasted back.
        """
        if self._params is not None and _attr(self._params, "session_token"):
            return  # already holding a live session; do not re-drive the browser

        api, vault, params, login_ui = self._load_sdk()
        logger.info("Starting Keeper SSO login for %s", self._username)
        try:
            # `login_ui` is why this is safe for an SSO-only account: left at
            # None, Commander installs a ConsoleLoginUi that getpass()es for a
            # master password on REQUIRES_AUTH_HASH and offers an "SSO User with
            # a Master Password" option. Ours cancels both.
            api.login(params, login_ui=login_ui)
        except KeyboardInterrupt:
            self.close()
            # Commander raises KeyboardInterrupt as *control flow*:
            # `loginv3.handleSsoRedirect` does that when it cannot prompt.
            # Confirmed live from a process with no controlling terminal, which
            # is what a non-interactive or MDM-launched session gets.
            if not sys.stdin.isatty():
                raise KeeperAuthError(
                    "Keeper SSO needs an interactive terminal and this process "
                    "has none. Commander prints an SSO URL and waits for the "
                    "token to be pasted back; with no TTY it cancels "
                    "immediately. Run the tool from Terminal, not from a "
                    "headless or non-interactive session."
                ) from None
            raise
        except Exception as exc:
            self.close()
            # The SDK's message can quote payloads; only the class name is safe.
            raise KeeperAuthError(
                f"Keeper SSO login failed ({type(exc).__name__}); no session was "
                "established"
            ) from exc

        if not _attr(params, "session_token"):
            self.close()
            raise KeeperAuthError(
                "Keeper SSO login returned no session token; the browser "
                "handshake was not completed"
            )

        self._api = api
        self._vault = vault
        self._params = params
        self._synced = False
        logger.info("Keeper SSO session established")

    def records(self) -> Iterator[KeeperRecord]:
        """Yield every record in the vault, normalized and secret-wrapped."""
        if self._params is None or self._api is None:
            raise KeeperReadError("records() called before authenticate()")
        self._sync()
        return self._iter_records()

    def close(self) -> None:
        """Destroy the session token and wipe cached auth material. Idempotent:
        the params reference is dropped first, so a second call has nothing left.
        """
        params, api = self._params, self._api
        self._params = None
        self._api = None
        self._vault = None
        self._synced = False
        if params is None:
            return

        # There is no `api.logout`. Commander's `logout` revokes server-side
        # first and only then calls the local-only `params.clear_session()`;
        # doing just the local half leaves a live token on the server.
        communicate_rest = getattr(api, "communicate_rest", None) if api is not None else None
        if callable(communicate_rest) and _attr(params, "session_token"):
            try:
                communicate_rest(params, None, LOGOUT_ENDPOINT)
            except Exception:
                logger.debug("Keeper server-side logout call failed; clearing locally")

        clear_session = getattr(params, "clear_session", None)
        if callable(clear_session):
            try:
                clear_session()
            except Exception:
                logger.debug("Keeper clear_session() failed; wiping params directly")

        # clear_session() may not exist, may miss an attribute, or may have
        # raised. Nothing secret survives this method.
        for attr in _SESSION_ATTRS:
            _safe_setattr(params, attr, None)
        for attr in _CACHE_ATTRS:
            _safe_setattr(params, attr, {})
        logger.info("Keeper session closed and cached auth material cleared")

    # -- internals ---------------------------------------------------------

    def _load_sdk(self) -> tuple[Any, Any, Any, Any]:
        """Import the SDK late; returns ``(api, vault_or_None, params, login_ui)``
        - ``vault`` optional, since the cache path covers pre-typed-record SDKs.
        """
        try:
            from keepercommander import api as sdk_api
            from keepercommander.auth import console_ui
            from keepercommander.params import KeeperParams

            api = _restricted(sdk_api, _ALLOWED_API_CALLS,
                              "keepercommander.api",
                              endpoints=frozenset({LOGOUT_ENDPOINT}))
        except Exception as exc:
            raise KeeperAuthError(
                "the keepercommander SDK is not available (or its auth UI module "
                "has moved); install the 'live' extra (pip install "
                "'otp-backfill[live]') to read a real Keeper vault"
            ) from exc

        try:
            from keepercommander import vault
        except Exception:
            # Pre-typed-record SDK. record_from_legacy handles that vault shape.
            vault = None

        params = KeeperParams()
        params.user = self._username
        if self._server:
            params.server = self._server
        params.password = ""  # SSO only; never collected, never prompted for
        # No "force SSO" flag exists; the server decides. The one key that would
        # divert us onto the master password is `sso_master_password`, so config
        # is pinned to a dict without it. 'file' storage plus the default empty
        # config_filename also stops store_config_properties() persisting
        # device_token, device_private_key, user and clone_code to the keychain.
        params.config = {"config_storage": "file"}
        return api, vault, params, sso_only_login_ui(console_ui)

    def _sync(self) -> None:
        if self._synced:
            return
        try:
            # record_types=True is not optional even here in the reader: the
            # writer's Login template comes from `params.record_type_cache`,
            # which ONLY sync_down populates when asked. Without it the two
            # halves disagree about what a Login record looks like.
            self._api.sync_down(self._params, record_types=True)
        except Exception as exc:
            raise KeeperReadError(
                f"Keeper vault sync failed ({type(exc).__name__})"
            ) from exc
        self._synced = True

    def _iter_records(self) -> Iterator[KeeperRecord]:
        params = self._params
        cache = _attr(params, "record_cache") or {}
        if not isinstance(cache, Mapping):
            raise KeeperReadError("Keeper record cache is not a mapping after sync")

        folders = shared_folders_index(params)
        uids = [_text(uid) for uid in cache]
        logger.info("Gathered metadata for %d Keeper record(s)", len(uids))

        for uid in uids:
            try:
                obj = _load_sdk_record(self._vault, params, uid) or cache.get(uid)
                record = to_keeper_record(obj, folders=folders.get(uid, ()))
            except Exception as exc:
                # One unreadable record must not cost the whole run.
                logger.warning("Skipping unreadable Keeper record %s (%s)",
                               uid, type(exc).__name__)
                continue
            if not record.uid:
                record = replace(record, uid=uid)
            yield record
#: How much of an SDK exception message is repeated back, after scrubbing.
_MAX_DETAIL_CHARS = 200

def _safe_detail(exc: BaseException) -> str:
    """A one-line, scrubbed rendering of an SDK exception. Commander's errors
    quote request payloads; the class name survives as the actionable part.
    """
    try:
        text = str(exc)
    except Exception:
        text = ""
    detail = scrub(text).replace("\n", " ").replace("\r", " ").strip()
    if len(detail) > _MAX_DETAIL_CHARS:
        detail = detail[:_MAX_DETAIL_CHARS] + "..."
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


# 6. The 1Password side
#
# Only metadata lives in this type. An item's own password and notes are never
# copied into a domain object: the adapter round-trips the raw JSON opaquely and
# nothing else in the module ever sees a value that is not the seed.


@dataclass(frozen=True)
class OpItem:
    """A 1Password item, reduced to what matching and the guard need."""

    item_id: str
    title: str
    vault: str
    username: str = ""
    #: True when the item already carries a one-time-password field. Presence is
    #: all that is ever read: this tool adds an OTP where there is none and never
    #: compares, replaces or even opens one that already exists.
    has_otp: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return (self.title.casefold().strip(), self.vault)


# 7. Matching, and the guard over it
#
# Writing a seed onto the wrong item is worse than not writing it. A missing OTP
# is visible at the next sign-in and still recoverable from Keeper; a wrong one
# silently attaches a second factor to an account it does not belong to, and the
# person it locks out is not the person who ran this. So every ambiguity becomes
# a flagged line rather than a write, and the guard fails closed.


class Outcome(str, Enum):
    """What happened, or would happen, to one Keeper record."""

    WOULD_ADD = "would_add"
    ADDED = "added"
    ALREADY_PRESENT = "already_present"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    NO_SEED = "no_seed"
    DUPLICATE = "duplicate"
    SKIPPED = "skipped"
    FAILED = "failed"


#: Outcomes that need a person. The exit code is built from these.
NEEDS_ATTENTION = frozenset({Outcome.NO_MATCH, Outcome.AMBIGUOUS, Outcome.FAILED})


@dataclass(frozen=True)
class Match:
    """The items a Keeper record resolved to, and whether that is safe."""

    outcome: Outcome
    reason: str
    items: tuple[OpItem, ...] = ()


def match_key(title: str) -> str:
    """The form two titles are compared in.

    NFC, not NFKC. Two vaults can hold the same title with different unicode
    normalization - an accented character composed in one and decomposed in the
    other - and those really are the same text, so folding them together only
    removes false "no match" lines. NFKC would go further and fold *compatibility*
    forms, making genuinely different titles compare equal, which in this tool
    means a confident write onto the wrong item. Inner whitespace is collapsed
    for the same reason: a non-breaking space is still a space.
    """
    normalized = unicodedata.normalize("NFC", title or "")
    # Drop invisible formatting characters. Real Keeper titles carry them: a
    # left-to-right mark in front of a title copied from a browser, directional
    # embedding around a phone number. They render as nothing, so two titles
    # that look identical to a person compare unequal, and the record is
    # reported as having no 1Password item when it plainly does. Confirmed on
    # live data, where it hid two genuine matches.
    visible = "".join(c for c in normalized
                      if unicodedata.category(c) != "Cf")
    return " ".join(visible.split()).casefold()


def match_items(record: KeeperRecord, items: Iterable[OpItem]) -> Match:
    """Resolve one Keeper record to the 1Password items it became.

    Title first, then username as a tiebreak, because a title alone is not an
    identity: "AWS Console" can be four accounts. Pure and total - no session,
    no I/O - so every branch below is testable without either vault.
    """
    title = match_key(record.title)
    if not title:
        return Match(Outcome.NO_MATCH, "the Keeper record has no title to match on")

    candidates = [i for i in items if match_key(i.title) == title]
    if not candidates:
        return Match(Outcome.NO_MATCH,
                     "no 1Password item has this title; it may not have been "
                     "imported, or it was renamed after the import")

    # Everything here already has a code, so there is nothing to decide and
    # nothing to get wrong. Checked before the ambiguity rules below, which
    # would otherwise flag a finished record forever: a title that exists in two
    # vaults can never stop being ambiguous, and a permanent NEEDS A PERSON line
    # teaches people to skip the section the real problems appear in.
    if all(i.has_otp for i in candidates):
        return Match(Outcome.ALREADY_PRESENT,
                     "already carries a one-time password; left untouched",
                     tuple(candidates))

    # Username narrows a title collision to one account.
    username = record.username.casefold().strip()
    if username:
        narrowed = [i for i in candidates
                    if i.username.casefold().strip() == username]
        if narrowed:
            candidates = narrowed
        elif any(i.username.strip() for i in candidates):
            # The Keeper record names an account and every candidate names a
            # different one. That is disagreement, not missing evidence, and
            # writing here puts someone's second factor on someone else's login.
            return Match(Outcome.AMBIGUOUS,
                         f"the Keeper record's username matches none of the "
                         f"{len(candidates)} item(s) with this title, so they "
                         "look like different accounts",
                         tuple(candidates))
        elif len(candidates) > 1:
            # Several same-titled items, none carrying a username to tell them
            # apart. Nothing to narrow with, so nothing may be guessed.
            return Match(Outcome.AMBIGUOUS,
                         f"{len(candidates)} items share this title and none "
                         "carries a username to tell them apart",
                         tuple(candidates))

    # Two same-titled items in two vaults are either one account shared into
    # both, or two different accounts that share a title. Nothing visible from
    # here separates those: the only evidence that would is the items' own
    # contents, and this tool does not read them. Guessing wrong writes a second
    # factor into a vault with a different audience, and it cannot take a field
    # back once written - so it refuses. Observed for real: two same-titled
    # records with the same username in different shared folders, and only one
    # of them ever had a seed.
    vaults = {i.vault for i in candidates}
    if len(vaults) > 1:
        # Keeper knows something 1Password cannot: which shared folders hold
        # this record. The migration made one vault per shared folder, so a
        # vault the record was never in did not get its item from this record.
        # That is disqualifying evidence, and it is metadata - no field value is
        # read to obtain it.
        #
        # Only ever NARROWS. If it does not resolve to exactly one vault the
        # refusal stands, so absent or ambiguous evidence still fails closed.
        home = {match_key(f) for f in record.folders}
        corroborated = [i for i in candidates if match_key(i.vault) in home]
        corroborated_vaults = {i.vault for i in corroborated}
        # Folder membership says which vault, never which account. It may break
        # a tie between candidates that agree about the account; it must not
        # pick between candidates the tool already knows are different accounts.
        #
        # Without this, adding one folder name flips a refusal into a write in
        # exactly the case with the least account-level evidence: candidates
        # whose usernames positively disagree, and a record naming neither.
        # Narrowing to one candidate would then skip the different-usernames
        # refusal below, because that test needs more than one candidate.
        named = {i.username.casefold().strip() for i in candidates
                 if i.username.strip()}
        if len(named) > 1:
            return Match(Outcome.AMBIGUOUS,
                         f"matches {len(candidates)} items across "
                         f"{len(vaults)} vaults ({', '.join(sorted(vaults))}) "
                         "with different usernames, so they are different "
                         "accounts. Keeper's folders say which vault this "
                         "record came from, but not which account it is",
                         tuple(candidates))
        if len(corroborated_vaults) == 1:
            ruled_out = sorted(vaults - corroborated_vaults)
            candidates = corroborated
            vaults = corroborated_vaults
            note = (f" (Keeper has this record in {corroborated_vaults.copy().pop()}"
                    f", not {', '.join(ruled_out)})")
        else:
            return Match(Outcome.AMBIGUOUS,
                         f"matches {len(candidates)} items across {len(vaults)} "
                         f"vaults ({', '.join(sorted(vaults))}); this may be one "
                         "account shared into both, or two different accounts "
                         "with the same title. Keeper's own folders do not "
                         "settle it"
                         + (f" (it is in {', '.join(record.folders)})"
                            if record.folders else
                            " (it is in no shared folder)"),
                         tuple(candidates))
    else:
        note = ""

    # One vault, but still several items. Same username means one account
    # duplicated by repeated imports, which is safe to write to all of.
    # Different usernames mean different accounts sharing a title, which is not.
    usernames = {i.username.casefold().strip() for i in candidates}
    if len(candidates) > 1 and len(usernames) > 1:
        return Match(Outcome.AMBIGUOUS,
                     f"matches {len(candidates)} items in {vaults.pop()} with "
                     "different usernames, so they are different accounts",
                     tuple(candidates))

    # Never replace an OTP that is already there. Not a comparison: an existing
    # one is left unopened, so a seed we did not put there cannot be read,
    # logged, or silently overwritten by a rerun.
    #
    # Filtering these out happens *after* the ambiguity rules on purpose.
    # Dropping the finished items first could collapse a genuinely ambiguous set
    # down to one and turn a refusal into a confident wrong write.
    writable = tuple(i for i in candidates if not i.has_otp)
    if not writable:
        # The check at the top ran against the *unnarrowed* list. Narrowing by
        # username can leave a subset that is entirely done: three items share a
        # title, only the one matching this username already has a code. That is
        # still "nothing to do", not an error.
        return Match(Outcome.ALREADY_PRESENT,
                     "already carries a one-time password; left untouched",
                     tuple(candidates))
    where = f"{len(writable)} item(s) in {writable[0].vault}"
    return Match(Outcome.WOULD_ADD, f"would add the seed to {where}{note}", writable)


# 8. The 1Password adapter - the only place the `op` CLI exists
#
# The CLI rather than the SDK, for two reasons that both matter here. It is
# already installed and already authenticated against the desktop app, so there
# is no second credential path and no new dependency to vet; and a service
# account cannot reach Employee/Private vaults at all, which is where most of
# these items live.
#
# Two rules are enforced here rather than trusted to callers:
#
# (a) A seed never becomes a command argument. `op` says so itself - "Command
#    arguments can be visible to other processes on your machine" - so the write
#    goes through a JSON template on **stdin**, never argv, and never a file.
# (b) The item is round-tripped whole and opaquely. The tool appends one field
#    and hands the rest straight back without reading it, so a password it never
#    looked at cannot be mangled by a partial template.


class OpError(RuntimeError):
    """The `op` CLI failed, is missing, or is not signed in."""


#: How many `op` calls may be in flight at once. Each is a process talking to
#: the 1Password desktop app; a small number is a large speedup over serial
#: without giving the app a reason to start refusing.
_OP_PARALLEL = 8

#: How long any one `op` call may take. A vault listing on a large account is
#: slow; a hung one that never returns is worse than a clean failure.
_OP_TIMEOUT = 120

#: 1Password derives a field's OTP-ness from its id, not only its type: an id of
#: "one-time password" yields a CONCEALED field that generates nothing, while a
#: `TOTP_<hex>` id yields a real OTP field. Confirmed against `op` 2.39.0 with
#: --dry-run, comparing the template form against the documented assignment form.
_OTP_FIELD_ID_PREFIX = "TOTP_"

_OTP_FIELD_LABEL = "one-time password"

#: Anything in an item's JSON that suggests it carries a passkey.
#:
#: `op item edit --help` says, unconditionally: "JSON item templates do not
#: support passkeys. If you use a JSON template to update an item that contains
#: a passkey, the passkey will be overwritten." The write below IS that path, so
#: an item with a passkey must not go through it.
#:
#: This is best effort and known to be incomplete: `op` 2.39.0 does not appear
#: to emit passkeys in `--format=json` at all, so an item can carry one that
#: this cannot see. It is a floor, not a guarantee, and the README says so.
_PASSKEY_MARKERS = ("passkey", "webauthn", "userhandle", "credentialid")

#: What a generated TOTP code looks like. Checked for *shape*, never printed.
#: Mere non-emptiness is not enough: `op` conceals sensitive values in some
#: modes and substitutes a placeholder, and a placeholder is non-empty, so
#: "is there a code?" would answer yes for any OTP field at all.
_CODE_SHAPE = re.compile(r"\d{6,8}")

#: Field labels that name the account, for item categories where 1Password does
#: not mark one with purpose=USERNAME.
_USERNAME_LABELS = frozenset({"username", "user", "login", "email",
                              "user name", "account", "login name"})

#: What `op` substitutes for a value it is concealing.
_CONCEALED_PLACEHOLDER = "--reveal' to reveal]"


class OnePasswordCli:
    """Reads and writes 1Password through the `op` CLI."""

    def __init__(self, account: str | None = None,
                 runner: "Callable[..., Any] | None" = None) -> None:
        self._account = (account or "").strip()
        # Injected only by the tests, which drive the real argv-building and
        # JSON-shaping code against a fake `op` rather than around it.
        self._run_process = runner or subprocess.run

    def _run(self, *args: str, stdin: str | None = None,
             reveal: bool = False) -> str:
        argv = ["op", *args, "--format=json"]
        if reveal:
            argv.append("--reveal")
        if self._account:
            argv += ["--account", self._account]
        try:
            done = self._run_process(argv, input=stdin, capture_output=True,
                                     text=True, timeout=_OP_TIMEOUT)
        except FileNotFoundError as exc:
            raise OpError(
                "the 1Password CLI (`op`) is not installed or not on PATH"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise OpError(f"`op {args[0]}` did not finish within "
                          f"{_OP_TIMEOUT}s") from exc
        if done.returncode != 0:
            raise OpError(f"`op {' '.join(args[:2])}` failed "
                          f"({_safe_detail_text(done.stderr)})")
        return done.stdout or ""

    @staticmethod
    def _parse(payload: str, what: str) -> Any:
        try:
            return json.loads(payload)
        except (ValueError, TypeError) as exc:
            raise OpError(f"could not read {what} from `op`: "
                          f"{_safe_detail(exc)}") from exc

    def items(self) -> tuple[OpItem, ...]:
        """Every item the signed-in user can see, as metadata only.

        The listing carries no field values at all, which is why the whole
        candidate search runs off it and only the few real candidates are
        fetched in full.
        """
        rows = self._parse(self._run("item", "list"), "the item list")
        found = []
        for row in rows or ():
            if not isinstance(row, Mapping):
                continue
            item_id = _text(row.get("id"))
            if not item_id:
                continue
            found.append(OpItem(
                item_id=item_id,
                title=_text(row.get("title")),
                vault=_text((row.get("vault") or {}).get("name")),
                # For a login, `op` puts the username here, which is enough to
                # shortlist. The real username is read from the detail fetch.
                username=_text(row.get("additional_information")),
            ))
        op_logger.info("Gathered metadata for %d 1Password item(s)", len(found))
        return tuple(found)

    def detail(self, item_id: str) -> OpItem:
        """One item's metadata, including whether it already has an OTP.

        Fetches the whole item because that is the only shape `op` offers, then
        keeps *none* of it beyond the few fields below.
        """
        raw = self._parse(self._run("item", "get", item_id), f"item {item_id}")
        return self._metadata(raw)

    @staticmethod
    def _metadata(raw: Any) -> OpItem:
        if not isinstance(raw, Mapping):
            # `op` returning null, a list or a bare string must be a clean
            # failure, not an AttributeError escaping as a traceback.
            raise OpError("1Password returned something that is not an item")
        fields = raw.get("fields") or []
        username = ""
        has_otp = False
        fallback = ""
        for field in fields:
            if not isinstance(field, Mapping):
                continue
            if _text(field.get("purpose")) == "USERNAME":
                username = _text(field.get("value"))
            elif not fallback and normalize_label(
                    _text(field.get("label")) or _text(field.get("id"))
            ) in _USERNAME_LABELS:
                # 1Password sets purpose=USERNAME only on Login and Password
                # categories. A Server, Database or API Credential item holds
                # the account in an ordinary field, so without this the username
                # tiebreak is silently unavailable for exactly the item types a
                # shared vault is full of, and a lone candidate gets a
                # title-only write with no corroboration.
                fallback = _text(field.get("value"))
            if _text(field.get("type")).upper() == "OTP":
                has_otp = True
        username = username or fallback
        return OpItem(
            item_id=_text(raw.get("id")),
            title=_text(raw.get("title")),
            vault=_text((raw.get("vault") or {}).get("name")),
            username=username,
            has_otp=has_otp,
        )

    def add_otp(self, item_id: str, seed: Secret) -> None:
        """Add a one-time-password field carrying ``seed``.

        The item is fetched, one field is appended, and the whole thing goes
        back on stdin. Nothing already on the item is read or rewritten.
        """
        payload = self._run("item", "get", item_id, reveal=True)
        if _CONCEALED_PLACEHOLDER in payload:
            # `op` conceals sensitive values in some output modes and puts a
            # placeholder in their place. --format=json does not do that today,
            # which is why the round-trip is safe; if that ever changes, posting
            # this payload back would overwrite every value with placeholder
            # text. Nothing else in the tool would notice, so refuse here.
            raise OpError(
                f"1Password returned concealed values for {item_id}; editing "
                "would overwrite them with placeholder text. Refusing.")
        raw = self._parse(payload, f"item {item_id}")
        if not isinstance(raw, MutableMapping):
            raise OpError(f"1Password returned no editable item for {item_id}")
        fields = raw.get("fields")
        if not isinstance(fields, list):
            fields = []
            raw["fields"] = fields
        if _looks_like_it_has_a_passkey(raw):
            raise OpError(
                f"item {item_id} looks like it carries a passkey. Editing it "
                "through a JSON template would destroy the passkey, so it is "
                "left alone; add the one-time password by hand in 1Password.")
        if any(isinstance(f, Mapping) and _text(f.get("type")).upper() == "OTP"
               for f in fields):
            # Belt and braces: the guard already refused these, and a race with
            # someone editing the item by hand must not silently replace a seed.
            raise OpError(f"item {item_id} already has a one-time password; "
                          "refusing to touch it")
        fields.append({
            "id": _OTP_FIELD_ID_PREFIX + secrets.token_hex(13),
            "type": "OTP",
            "label": _OTP_FIELD_LABEL,
            # The single place a Secret is opened on the 1Password side. It goes
            # straight into the payload and onto stdin; it is never formatted
            # into a message, a log line or an argument.
            "value": _unwrap(seed),
        })
        self._run("item", "edit", item_id, stdin=json.dumps(raw))

    def generates_a_code(self, item_id: str) -> bool:
        """True if 1Password can actually produce a code from what was written.

        The strongest check available without ever displaying one: `op` returns
        the current code alongside an OTP field, so a non-empty one proves the
        seed was stored in a form 1Password understands. The code itself is
        looked at only for emptiness and is never returned or logged.
        """
        raw = self._parse(self._run("item", "get", item_id, reveal=True),
                          f"item {item_id}")
        fields = raw.get("fields") or [] if isinstance(raw, Mapping) else []
        for field in fields:
            if (isinstance(field, Mapping)
                    and _text(field.get("type")).upper() == "OTP"
                    and _CODE_SHAPE.fullmatch(_text(field.get("totp")))):
                return True
        return False


def _looks_like_it_has_a_passkey(raw: Any) -> bool:
    """Best-effort passkey detection over an item payload.

    Structure only: a top-level key, or a field's id/type/purpose. Never a
    *value*, and never the title, notes, urls or tags. Scanning values reads
    "Also registered a passkey on the MacBook" in a note, or a url of
    webauthn.io, or a password that happens to contain the word, and refuses the
    item forever - on every rerun, since nothing about it changes. Mid-migration
    those notes are common, while `op` 2.39.0 does not appear to emit passkeys
    in --format=json at all, so scanning values costs much and catches nothing.
    """
    def marked(name: Any) -> bool:
        text = name.casefold() if isinstance(name, str) else ""
        return any(marker in text for marker in _PASSKEY_MARKERS)

    try:
        if not isinstance(raw, Mapping):
            return False
        if any(marked(k) for k in raw):
            return True
        for field in raw.get("fields") or ():
            if not isinstance(field, Mapping):
                continue
            if any(marked(field.get(k)) for k in ("id", "type", "purpose")):
                return True
            if any(marked(k) for k in field):
                return True
        for section in raw.get("sections") or ():
            if isinstance(section, Mapping) and any(marked(k) for k in section):
                return True
    except (AttributeError, TypeError):
        # Unjudgeable, and this decides whether a destructive edit is allowed.
        return True
    return False


def _safe_detail_text(text: str | None) -> str:
    """Scrub and cap CLI stderr before it reaches a message."""
    cleaned = scrub(_text(text)).strip().replace("\n", "; ")
    if len(cleaned) > _MAX_DETAIL_CHARS:
        cleaned = cleaned[:_MAX_DETAIL_CHARS] + "..."
    return cleaned or "no detail"


# 9. Orchestration: read Keeper -> match -> guard -> write 1Password -> verify
#
# One pass. Everything is read before anything is written, so a read that dies
# half way leaves nothing half written, and the preview a person approves is
# built from the same data the apply then uses.


class EngineError(RuntimeError):
    """The run could not start or could not finish."""


@dataclass
class EngineOptions:
    apply: bool = False
    verify: bool = True
    #: Exact titles to limit the run to. Empty means every record.
    only: tuple[str, ...] = ()
    #: Asked with the preview, before anything is written. Returning False
    #: leaves the vault untouched.
    confirm: "Callable[[RunSummary], bool] | None" = None


@dataclass
class RecordResult:
    title: str
    uid: str
    outcome: Outcome
    detail: str = ""
    vault: str = ""
    item_ids: tuple[str, ...] = ()
    verified: bool = False

    @property
    def needs_attention(self) -> bool:
        return self.outcome in NEEDS_ATTENTION


@dataclass
class RunSummary:
    results: list[RecordResult] = field(default_factory=list)
    records_read: int = 0
    seeds_found: int = 0
    items_read: int = 0
    dry_run: bool = True
    #: --only values that matched no Keeper record title. A typo otherwise
    #: produces a clean, empty, entirely normal-looking report.
    unmatched_only: tuple[str, ...] = ()
    #: Every identifier this run actually saw: 1Password item ids from the
    #: listing, Keeper record uids from the vault. Only these may be held out
    #: of the scrubber - see _identifiers.
    known_ids: frozenset = frozenset()

    def add(self, result: RecordResult) -> None:
        self.results.append(result)

    @property
    def counts(self) -> dict[str, int]:
        tally = Counter(r.outcome.value for r in self.results)
        return {o.value: tally.get(o.value, 0) for o in Outcome}

    @property
    def flagged(self) -> list[RecordResult]:
        return [r for r in self.results if r.needs_attention]

    @property
    def actionable(self) -> list[RecordResult]:
        """What a dry run would go on to do. Empty means there is nothing to
        apply, which is what lets a run stop before asking anyone anything."""
        return [r for r in self.results if r.outcome is Outcome.WOULD_ADD]

    @property
    def written(self) -> list[RecordResult]:
        return [r for r in self.results if r.outcome is Outcome.ADDED]

    @property
    def exit_code(self) -> int:
        """0 = clean, 1 = something needs a person."""
        return 1 if self.flagged else 0

    def to_dict(self) -> dict:
        """A JSON view. Holds counts, titles, vaults and item ids - no value
        from either vault, by construction."""
        return {
            "dry_run": self.dry_run,
            "records_read": self.records_read,
            "seeds_found": self.seeds_found,
            "items_read": self.items_read,
            "counts": self.counts,
            "unmatched_only": list(self.unmatched_only),
            "records": [
                {
                    "title": r.title,
                    "uid": r.uid,
                    "outcome": r.outcome.value,
                    "detail": r.detail,
                    "vault": r.vault,
                    "item_ids": list(r.item_ids),
                    "verified": r.verified,
                }
                for r in self.results
            ],
        }


class BackfillEngine:
    """Reads Keeper, decides, and writes 1Password."""

    def __init__(self, reader: Any, op: Any,
                 options: EngineOptions | None = None) -> None:
        self.reader = reader
        self.op = op
        self.options = options or EngineOptions()
        self._details: dict[str, OpItem] = {}

    def run(self) -> RunSummary:
        options = self.options
        try:
            records = list(self.reader.records())
        except Exception as exc:
            raise EngineError(f"could not read the Keeper vault "
                              f"({_safe_detail(exc)})") from exc
        log.info("gathered metadata for %d Keeper record(s)", len(records))

        items = self.op.items()
        self._prefetch(records, items)

        if options.confirm is not None and options.apply:
            preview = self._pass(records, items, writing=False)
            if not preview.actionable or not options.confirm(preview):
                return preview
            return self._pass(records, items, writing=True)
        return self._pass(records, items, writing=options.apply)

    def _prefetch(self, records: "list[KeeperRecord]",
                  items: "tuple[OpItem, ...]") -> None:
        """Fetch the item details this run will need, concurrently.

        `op item get` costs about a second, mostly waiting on the desktop app,
        and a run needs one per candidate item - two minutes of it on a real
        vault, spent after the last log line with nothing on screen. That reads
        as a hang, and a person watching a tool that writes to a password vault
        should never be left guessing whether it is stuck.

        Fetching is read-only and each item is independent, so they overlap. A
        small pool on purpose: every call is a process talking to the 1Password
        app, and hammering it is a good way to find a rate limit.

        Failures are swallowed here. The per-record path re-fetches anything
        missing from the cache and turns the error into that record's own
        result, which is where it belongs.
        """
        wanted, seen = [], set()
        for record in records:
            if not find_seed_fields(record).fields or not self._in_scope(record):
                continue
            title = match_key(record.title)
            for item in items:
                if match_key(item.title) == title and item.item_id not in seen:
                    seen.add(item.item_id)
                    wanted.append(item.item_id)
        if not wanted:
            return

        op_logger.info("Reading %d candidate 1Password item(s)...", len(wanted))
        done = 0
        with ThreadPoolExecutor(max_workers=_OP_PARALLEL) as pool:
            futures = {pool.submit(self.op.detail, i): i for i in wanted}
            for future in as_completed(futures):
                item_id = futures[future]
                try:
                    self._details[item_id] = future.result()
                except Exception:
                    pass  # re-fetched serially later, and reported per record
                done += 1
                if done % 25 == 0 or done == len(wanted):
                    op_logger.info("  ...%d of %d", done, len(wanted))

    def _pass(self, records: list[KeeperRecord], items: tuple[OpItem, ...],
              *, writing: bool) -> RunSummary:
        summary = RunSummary(dry_run=not writing, records_read=len(records),
                             items_read=len(items),
                             known_ids=frozenset(
                                 {i.item_id for i in items}
                                 | {r.uid for r in records if r.uid}))
        # Which record already resolved to a given item during *this* pass. Two
        # Keeper records with one title would otherwise race: the first write
        # flips has_otp, and the second silently reports "already present" and
        # drops a seed that never reached 1Password. It also keeps the preview
        # and the apply agreeing, since the preview writes nothing and would
        # otherwise plan two writes where the apply performs one.
        # item id -> (the record that claimed it, the seed it will get)
        claimed: dict[str, tuple[str, Secret]] = {}
        # (record uid, the items it resolved to, its seed) for every record so
        # far this pass, so a twin can be recognised whatever the outcome.
        resolved: list[tuple[str, frozenset, Secret]] = []
        for record in records:
            search = find_seed_fields(record)
            if not search.fields:
                summary.add(RecordResult(record.title, record.uid,
                                         Outcome.NO_SEED))
                continue
            if not self._in_scope(record):
                # Not counted as a seed and not counted as seedless: it was
                # never looked at, and filing it under either makes the two
                # tallies in the report contradict each other.
                summary.add(RecordResult(record.title, record.uid,
                                         Outcome.SKIPPED,
                                         "outside --only, not examined"))
                continue
            summary.seeds_found += 1
            if search.has_conflict:
                # Several *custom* fields holding different values, with no
                # natively typed field to settle it. Which one is live is not
                # decidable without opening and parsing them, so it goes to a
                # person. Only the conflicting fields are named.
                custom = [f.label for f in search.fields if not f.is_native]
                summary.add(RecordResult(
                    record.title, record.uid, Outcome.AMBIGUOUS,
                    f"carries {len(custom)} different 2FA fields "
                    f"({', '.join(custom)}); which one is current cannot be "
                    "decided without reading them"))
                continue
            # A natively typed field wins: Keeper set that type itself, so a
            # custom field beside it is a leftover from before.
            chosen = search.native or search.fields[0]
            summary.add(self._one(record, chosen.value, items, writing,
                                  claimed, resolved))
        seen = {match_key(r.title) for r in records}
        summary.unmatched_only = tuple(
            t for t in self.options.only if match_key(t) not in seen)
        return summary

    def _in_scope(self, record: KeeperRecord) -> bool:
        if not self.options.only:
            return True
        return match_key(record.title) in {match_key(t) for t in self.options.only}

    def _one(self, record: KeeperRecord, seed: Secret,
             items: tuple[OpItem, ...], writing: bool,
             claimed: "dict[str, tuple[str, Secret]]",
             resolved: "list[tuple[str, frozenset, Secret]]") -> RecordResult:
        # The listing has no OTP information on it, so shortlist on titles
        # first and only then pay for a detail fetch per candidate.
        title = match_key(record.title)
        shortlist = [i for i in items if match_key(i.title) == title]
        detailed: list[OpItem] = []
        for candidate in shortlist:
            try:
                detailed.append(self._detail(candidate.item_id))
            except OpError as exc:
                return RecordResult(record.title, record.uid, Outcome.FAILED,
                                    f"could not read the 1Password item "
                                    f"({_safe_detail(exc)})")

        match = match_items(record, detailed)
        vault = match.items[0].vault if match.items else ""
        ids = tuple(i.item_id for i in match.items)

        # Only the items this record actually resolved to can collide with
        # another record. Testing every item that merely *shares the title*
        # refuses the common case outright: two accounts on one title, each
        # matching its own item by username, where the second is turned away
        # because the first claimed a different item. That converges at one
        # write per title per run, and every run is a fresh SSO sign-in.
        #
        # Checked for every outcome, not just WOULD_ADD: it is also what stops
        # a second seed being swallowed by an ALREADY_PRESENT read off the
        # cache after the first record wrote.
        # A twin that resolved to the same items with the same seed is a
        # duplicate whatever the outcome. Claiming only happens on a write path,
        # so without this two twins that both *refuse* - a title present in two
        # vaults, say - each print the identical unresolvable line.
        # Only a record that resolved to the SAME, NON-EMPTY item set with the
        # same seed and the same title is a twin. Without the emptiness test,
        # two records that both matched nothing compare equal on frozenset()
        # and the second is filed as a duplicate - moved out of the list that
        # needs a person, under a message claiming a title it does not have.
        # Two records sharing a seed but not a title ("AWS prod" and "AWS prod
        # (old)") is an ordinary shape mid-migration, and the second one still
        # needs its own 1Password item.
        # `ids` non-empty is the whole test. Every item a record resolves to
        # carries that record's own title key, so an identical non-empty item
        # set already implies an identical title - comparing titles as well
        # would be redundant code nothing exercises.
        if ids:
            for owner, other_ids, other_seed in resolved:
                if other_ids == frozenset(ids) and other_seed == seed:
                    return RecordResult(
                        record.title, record.uid, Outcome.DUPLICATE,
                        f"another Keeper record ({owner}) with the same title "
                        "carries an identical seed and resolves the same way",
                        vault, ids)
        resolved.append((record.uid, frozenset(ids), seed))

        taken = [i for i in match.items
                 if i.item_id in claimed and claimed[i.item_id][0] != record.uid]
        if taken:
            owner, other_seed = claimed[taken[0].item_id]
            # Two Keeper records, one title, and the *same* seed: a duplicate,
            # which the vault is full of after a conversion pass. There is
            # nothing to decide, so it is not a question for a person. The
            # comparison is Secret.__eq__, constant time over the encoded bytes,
            # and neither value is opened to make it.
            if other_seed == seed:
                return RecordResult(
                    record.title, record.uid, Outcome.DUPLICATE,
                    f"another Keeper record ({owner}) with the same title "
                    "carries an identical seed and covers this item",
                    taken[0].vault, tuple(i.item_id for i in taken))
            return RecordResult(
                record.title, record.uid, Outcome.AMBIGUOUS,
                f"another Keeper record ({owner}) with the same title resolves "
                "to this item with a DIFFERENT seed, so which one belongs here "
                "cannot be decided here",
                taken[0].vault, tuple(i.item_id for i in taken))

        if match.outcome is not Outcome.WOULD_ADD:
            return RecordResult(record.title, record.uid, match.outcome,
                                match.reason, vault, ids)
        for item in match.items:
            claimed[item.item_id] = (record.uid, seed)
        if not writing:
            return RecordResult(record.title, record.uid, Outcome.WOULD_ADD,
                                match.reason, vault, ids)

        # Written, failed and never-attempted are three different things, and
        # the person cleaning up after a partial failure needs to know which is
        # which. Reporting the whole match as failed sends them to items that
        # are fine and hides the one that is not.
        written: list[str] = []
        unverified: list[str] = []
        for position, item in enumerate(match.items):
            try:
                self.op.add_otp(item.item_id, seed)
            except OpError as exc:
                skipped = [i.item_id for i in match.items[position + 1:]]
                detail = f"the write failed on {item.item_id} " \
                         f"({_safe_detail(exc)})"
                good = [w for w in written if w not in unverified]
                if good:
                    detail += f"; already written: {', '.join(good)}"
                if unverified:
                    # Must not be folded in with the successes: these carry a
                    # field that generates nothing, and a rerun will treat them
                    # as done. Saying "already written" would hide that.
                    detail += (f"; written but generating NO code (delete the "
                               f"one-time password field by hand, then rerun): "
                               f"{', '.join(unverified)}")
                if skipped:
                    detail += f"; not attempted: {', '.join(skipped)}"
                return RecordResult(record.title, record.uid, Outcome.FAILED,
                                    detail, vault, ids)
            written.append(item.item_id)
            log.info("added a one-time password to %r in %s",
                     record.title, item.vault)
            if self.options.verify and not self._verified(item.item_id):
                unverified.append(item.item_id)
        # Never claim proof that was not sought.
        verified = self.options.verify and not unverified
        if unverified:
            # The field exists but produces no code, and this tool cannot
            # remove a field it wrote. Say so plainly: a rerun would find an
            # item that "already has a one-time password" and skip it, so
            # without this line the problem disappears on the next run.
            return RecordResult(
                record.title, record.uid, Outcome.FAILED,
                f"written to {', '.join(unverified)}, but 1Password generates "
                "no code from it. The field is there, so a rerun will treat "
                "this item as done: delete the one-time password field by hand, "
                "then run again.",
                vault, ids)

        detail = ("verified: 1Password generates a code from what was written"
                  if self.options.verify else
                  "written (verification skipped)")
        return RecordResult(record.title, record.uid, Outcome.ADDED, detail,
                            vault, ids, verified=verified)

    def _detail(self, item_id: str) -> OpItem:
        """One item's detail, fetched at most once per run.

        --confirm walks every record twice, and a title with a dozen duplicates
        turns that into two dozen serialised `op` calls for one record. The
        preview writes nothing, so the state it saw is still the state the apply
        starts from, and reusing it makes the two passes provably consistent
        rather than merely usually consistent.
        """
        cached = self._details.get(item_id)
        if cached is None:
            cached = self.op.detail(item_id)
            self._details[item_id] = cached
        return cached

    def _verified(self, item_id: str) -> bool:
        try:
            return bool(self.op.generates_a_code(item_id))
        except OpError:
            return False


# 10. The report
#
# Counts, titles, vaults and item ids. Every string that could carry a value
# from either vault goes through scrub() on the way out.

#: 1Password item ids are 26 characters of lowercase base32 alphabet and Keeper
#: record uids are 22 of base64url, so the bare-seed rules in scrub() match many
#: of them. Redacting an identifier would be harmless if it were decoration, but
#: it is the one field a person uses to go and find the record, so a report full
#: of <redacted> is unusable. Identifiers are held out of the text while it is
#: scrubbed and put back after: every one is a value this tool read from an id
#: field, never vault content.
_ID_TOKEN = "\x00id{}\x00"

#: Below this length an "identifier" is not distinctive enough to hold out of
#: the scrubber: a short string could appear inside real secret material and
#: shield a fragment of it. Real ids are 22 (Keeper) or 26 (1Password).
_MIN_ID_LENGTH = 16


def _scrub_preserving_ids(page: str, identifiers: "set[str]") -> str:
    # Longest first, so one identifier that contains another cannot be half
    # replaced and left unrecognisable.
    ordered = sorted((i for i in identifiers if i and len(i) >= _MIN_ID_LENGTH),
                     key=len, reverse=True)
    for index, identifier in enumerate(ordered):
        page = page.replace(identifier, _ID_TOKEN.format(index))
    page = scrub(page)
    for index, identifier in enumerate(ordered):
        page = page.replace(_ID_TOKEN.format(index), identifier)
    return page


def _identifiers(summary: RunSummary) -> "set[str]":
    """Every id this run knows about, so none of them is redacted.

    Details are scanned too: a failed detail read names its item id in the
    message and carries no item_ids of its own, and that line is exactly the one
    a person needs in order to go and look.
    """
    known = {r.uid for r in summary.results}
    known |= {i for r in summary.results for i in r.item_ids}
    # A detail line names an item id when the read of that item failed, and
    # that line carries no item_ids of its own. Harvest those - but only ones
    # the run has actually seen. `detail` also carries vault names, folder
    # names and Keeper field labels, all of them text from the vault, and a
    # token that merely *looks* like an id would otherwise be lifted out of
    # scrub()'s reach and restored verbatim. A 22-character base32 seed sitting
    # in a field label is exactly that shape.
    for result in summary.results:
        for token in re.findall(r"\b[A-Za-z0-9_-]{22,26}\b", result.detail):
            if token in summary.known_ids:
                known.add(token)
    return known


#: Outcomes a person has to act on, in the order they matter. Everything else
#: is collapsed to a count: a run over 1500 records that prints three lines for
#: each of 58 items nobody needs to touch buries the four that they do.
_ACTION_SECTIONS: tuple[tuple[str, str, tuple[Outcome, ...]], ...] = (
    ("NEEDS A PERSON", "!", (Outcome.FAILED, Outcome.AMBIGUOUS,
                             Outcome.NO_MATCH)),
)

#: Collapsed counts, in reporting order: (outcome, singular, plural). Spelled
#: out rather than derived: "58 already had a codes" is the kind of thing that
#: makes a report look unreviewed.
_QUIET_SECTIONS: tuple[tuple[Outcome, str, str], ...] = (
    (Outcome.ALREADY_PRESENT, "already had a code", "already had a code"),
    (Outcome.DUPLICATE, "duplicate Keeper record", "duplicate Keeper records"),
    (Outcome.NO_SEED, "with no 2FA seed", "with no 2FA seed"),
    (Outcome.SKIPPED, "outside --only", "outside --only"),
)


def render_summary(summary: RunSummary, verbose: bool = False) -> str:
    """The run, as a person needs to read it.

    Written vs needs-a-person first and in full; everything requiring no action
    collapsed to one line, and listed only under --verbose.
    """
    heading = ("OTP backfill - DRY RUN, nothing was written" if summary.dry_run
               else "OTP backfill")
    out = [heading, "=" * len(heading), ""]

    done = summary.actionable if summary.dry_run else summary.written
    if done:
        verb = "WOULD ADD a code to" if summary.dry_run else "ADDED a code to"
        out.append(f"{verb} {sum(len(r.item_ids) for r in done)} "
                   f"1Password item(s), from {len(done)} Keeper record(s):")
        for row in done:
            out.extend(_row("+", row))
        out.append("")

    for label, mark, outcomes in _ACTION_SECTIONS:
        rows = [r for r in summary.results if r.outcome in outcomes]
        if not rows:
            continue
        out.append(f"{label} ({len(rows)}) - not written:")
        for row in rows:
            out.append(f"  {mark} {row.title}{_where(row)}")
            if row.detail:
                out.append(f"      {row.detail}")
            if row.item_ids:
                out.append(f"      {', '.join(row.item_ids)}")
        # A flagged row keeps its own lines: the reason is the point of it.
        out.append("")

    quiet = [(outcome, one, many, summary.counts.get(outcome.value, 0))
             for outcome, one, many in _QUIET_SECTIONS]
    tally = "   ".join(f"{count} {one if count == 1 else many}"
                       for _, one, many, count in quiet if count)
    if tally:
        out.append(f"Nothing to do:  {tally}")
    out.append(f"Read {summary.records_read} Keeper record(s) "
               f"({summary.seeds_found} with a 2FA seed) against "
               f"{summary.items_read} 1Password item(s).")

    if verbose:
        for outcome, one, many, count in quiet:
            rows = [r for r in summary.results if r.outcome is outcome]
            if not rows or outcome is Outcome.NO_SEED:
                continue
            out.append("")
            out.append(f"{one if count == 1 else many} ({count}):")
            for row in rows:
                out.append(f"  = {row.title}{_where(row)}")

    if summary.unmatched_only:
        out.append("")
        out.append("--only matched no Keeper record for: "
                   + ", ".join(summary.unmatched_only))
    return _scrub_preserving_ids("\n".join(out).rstrip() + "\n",
                                 _identifiers(summary))


def _where(row: RecordResult) -> str:
    return f" [{row.vault}]" if row.vault else ""


#: Wrap width for a one-line entry. Past this the ids go on their own line
#: rather than wrapping mid-identifier, which makes them hard to copy.
_LINE_BUDGET = 100


def _row(mark: str, row: RecordResult) -> "list[str]":
    """One entry, on one line where it fits."""
    head = f"  {mark} {row.title}{_where(row)}"
    ids = ", ".join(row.item_ids)
    if not ids:
        return [head]
    if len(head) + len(ids) + 2 <= _LINE_BUDGET:
        return [f"{head}  {ids}"]
    return [head, f"      {ids}"]


def _plural(count: int, wording: str) -> str:
    """"1 duplicate Keeper record", "2 duplicate Keeper records"."""
    if count == 1 or not wording.endswith(("record", "code", "seed")):
        return f"{count} {wording}"
    return f"{count} {wording}s"


def write_json_summary(summary: RunSummary, path: str) -> None:
    """Write the summary as JSON, mode 0600."""
    target = Path(path).expanduser()
    payload = json.dumps(summary.to_dict(), indent=2, sort_keys=True)
    handle = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as stream:
        stream.write(_scrub_preserving_ids(payload, _identifiers(summary)) + "\n")
    os.chmod(target, 0o600)


# 11. The command line

EXIT_OK = 0
EXIT_NEEDS_ATTENTION = 1
EXIT_FATAL = 2


class UsageError(RuntimeError):
    """Bad arguments, or a prerequisite that is not there."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="otp-backfill",
        description="Copy the 2FA seeds the Keeper import dropped onto the "
                    "1Password items that should already have them. Reports "
                    "only by default: nothing is written without --apply, and "
                    "an item that already has a code is never changed.")
    parser.add_argument("--version", action="version",
                        version=f"otp-backfill {__version__}")
    parser.add_argument("--apply", action="store_true",
                        help="actually write to 1Password. Without this the "
                             "run is a preview and changes nothing.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="debug logging on stderr (still redacted)")
    parser.add_argument("--json-summary", metavar="PATH",
                        help="also write the summary as JSON (mode 0600; "
                             "counts, titles, vaults and item ids only)")
    parser.add_argument("--confirm", action="store_true",
                        help="with --apply: show what would change, ask, and "
                             "then apply in the same session. One sign-in.")
    parser.add_argument("--only", metavar="TITLE", action="append", default=[],
                        help="only this exact record title; repeatable")
    parser.add_argument("--keeper-user", metavar="EMAIL",
                        help="Keeper account to sign in as (SSO; no password "
                             "is ever collected)")
    parser.add_argument("--keeper-server", metavar="HOST",
                        help="Keeper region host, if not the default")
    parser.add_argument("--op-account", metavar="ACCOUNT",
                        help="1Password account, if `op` knows more than one")
    return parser


def build_options(args: argparse.Namespace) -> EngineOptions:
    return EngineOptions(
        apply=bool(args.apply),
        only=tuple(args.only or ()),
        confirm=_ask_to_apply if (args.confirm and args.apply) else None,
    )


# Used only to offer a default at the interactive prompt, which you can overtype.
# Set OTP_BACKFILL_EMAIL_DOMAIN to your own, or pass --keeper-user and skip it.
DEFAULT_EMAIL_DOMAIN = os.environ.get("OTP_BACKFILL_EMAIL_DOMAIN", "")


def guess_keeper_user() -> str:
    """The Mac account name as an email, offered for the person to correct.

    Interactive runs offer this
    and takes a different answer if it is wrong.
    """
    try:
        name = getpass.getuser().strip()
    except Exception:
        return ""
    return f"{name}@{DEFAULT_EMAIL_DOMAIN}" if name and DEFAULT_EMAIL_DOMAIN else ""


def resolve_keeper_user(explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    if not sys.stdin.isatty():
        raise UsageError("--keeper-user is required when there is no terminal "
                         "to ask at")
    guess = guess_keeper_user()
    prompt = f"Keeper email [{guess}]: " if guess else "Keeper email: "
    try:
        answer = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise UsageError("no Keeper email given") from None
    chosen = answer or guess
    if not chosen:
        raise UsageError("no Keeper email given")
    return chosen


def _ask_to_apply(preview: RunSummary) -> bool:
    """Show the preview and ask. Never asks about an empty list."""
    if not preview.actionable:
        return False
    print(render_summary(preview))
    try:
        return input("Apply these changes? Type yes to continue: "
                     ).strip().casefold() == "yes"
    except (EOFError, KeyboardInterrupt):
        print("\nNothing was written.")
        return False


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(verbose=args.verbose)
    reader = None
    try:
        username = resolve_keeper_user(args.keeper_user)
        op = OnePasswordCli(account=args.op_account)
        reader = CommanderKeeperReader(username, server=args.keeper_server)
        reader.authenticate()
        summary = BackfillEngine(reader, op, build_options(args)).run()
    except (UsageError, EngineError, OpError, KeeperAuthError,
            KeeperReadError) as exc:
        print(f"\n{scrub(str(exc))}", file=sys.stderr)
        return EXIT_FATAL
    except KeyboardInterrupt:
        print("\nStopped. Nothing was written.", file=sys.stderr)
        return EXIT_FATAL
    except Exception as exc:
        # Nothing unexpected may reach the terminal as a raw traceback. A
        # traceback does not print locals, so this is not a known leak, but the
        # whole point of the redaction discipline is that the tool decides what
        # is printed, not the interpreter.
        print(f"\nunexpected failure: {_safe_detail(exc)}", file=sys.stderr)
        return EXIT_FATAL
    finally:
        if reader is not None:
            reader.close()

    try:
        print(render_summary(summary, verbose=args.verbose))
        if args.json_summary:
            write_json_summary(summary, args.json_summary)
            print(f"Summary written to {args.json_summary}")
    except OSError as exc:
        print(f"\nthe run finished but the summary could not be written "
              f"({_safe_detail(exc)})", file=sys.stderr)
        return EXIT_FATAL
    return summary.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
