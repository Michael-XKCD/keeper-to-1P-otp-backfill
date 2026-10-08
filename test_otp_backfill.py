"""Tests for otp-backfill.

The tool's two dangerous failure modes are leaking a seed and writing one onto
the wrong item, so those are what is covered here: the `Secret` wrapper and the
scrubber that keep seeds out of logs and reports, the seed-detection rules, and
every branch of the matching guard.

All fixtures are synthetic. Seeds are the public RFC 6238 / Google Authenticator
demo vectors, never a real one.
"""

from __future__ import annotations

import logging
import pickle

import pytest

import otp_backfill
from otp_backfill import (
    KeeperField,
    KeeperRecord,
    Match,
    OpItem,
    Outcome,
    RecordType,
    Secret,
    SecretLeakError,
    contains_secret_material,
    find_seed_fields,
    label_suggests_otp,
    match_items,
    match_key,
    normalize_label,
    scrub,
)

# The public demo seed. Never a real one.
SEED = "JBSWY3DPEHPK3PXP"
SEED_B = "KRSXG5CTMVRXEZLU"


# -- helpers ------------------------------------------------------------------


def make_record(uid="RecordUidExample000001", title="Example Service",
                username="person@example.com", seed=SEED, *,
                seed_type="oneTimeCode", seed_label="", folders=(),
                extra=()):
    fields = []
    if username:
        fields.append(KeeperField("login", "", Secret(username)))
    if seed is not None:
        fields.append(KeeperField(seed_type, seed_label, Secret(seed)))
    fields.extend(extra)
    return KeeperRecord(uid=uid, title=title, record_type=RecordType.LOGIN,
                        folders=tuple(folders), fields=tuple(fields))


def make_item(item_id="itemidexample00000000000a", title="Example Service",
              vault="Team Vault", username="person@example.com", has_otp=False):
    return OpItem(item_id=item_id, title=title, vault=vault,
                  username=username, has_otp=has_otp)


# -- Secret: the primary containment ------------------------------------------


def test_secret_never_renders_its_value():
    s = Secret(SEED)
    assert SEED not in repr(s)
    assert SEED not in str(s)
    assert SEED not in f"{s}"
    assert SEED not in "{}".format(s)
    assert SEED not in format(s)


def test_secret_reveals_only_on_request():
    assert Secret(SEED).reveal() == SEED


def test_secret_refuses_to_pickle():
    # Pickling would write the value to whatever the caller does with the bytes.
    with pytest.raises(Exception):
        pickle.dumps(Secret(SEED))


def test_secret_is_unhashable():
    # Hashing would let a seed become a dict key or land in a set repr.
    with pytest.raises(TypeError):
        {Secret(SEED)}


def test_secret_compares_by_value_not_identity():
    assert Secret(SEED) == Secret(SEED)
    assert Secret(SEED) != Secret(SEED_B)


def test_secret_predicates_answer_without_revealing():
    assert Secret("").is_blank()
    assert not Secret(SEED).is_blank()
    assert Secret("otpauth://totp/x?secret=" + SEED).startswith("otpauth://")


# -- scrub: the net under Secret ----------------------------------------------


@pytest.mark.parametrize("text", [
    SEED,
    f"otpauth://totp/Example?secret={SEED}&issuer=Example",
    "JBSW Y3DP EHPK 3PXP",          # the spaced grouping vendors display
    "JBSW-Y3DP-EHPK-3PXP",          # and the hyphenated one
    "a" * 40,                       # hex-shaped
])
def test_scrub_removes_secret_shaped_text(text):
    assert SEED not in scrub(text)
    assert contains_secret_material(text)


@pytest.mark.parametrize("text", [
    "Example Service",
    "person@example.com",
    "2026-09-11",
    "Wrote 3 items, skipped 1",
    "Team Vault",
])
def test_scrub_leaves_the_report_readable(text):
    # Over-scrubbing makes the report useless, which is its own failure.
    assert scrub(text) == text
    assert not contains_secret_material(text)


def test_logging_redacts_a_seed_passed_as_an_argument():
    logger = logging.getLogger("otp_backfill.test")
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))

    handler = Capture()
    handler.setFormatter(otp_backfill.RedactingFormatter("%(message)s"))
    handler.addFilter(otp_backfill.RedactingFilter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        # Interpolation must happen before scrubbing, or the %s survives and the
        # seed does not get scrubbed.
        logger.info("writing %s", SEED)
    finally:
        logger.removeHandler(handler)

    assert records
    assert SEED not in records[0]


# -- seed detection -----------------------------------------------------------


def test_native_otp_field_is_found_and_marked_authoritative():
    search = find_seed_fields(make_record())
    assert search.native is not None
    assert search.native.value.reveal() == SEED


def test_otp_label_on_a_text_field_is_found():
    record = make_record(seed=None, extra=(
        KeeperField("text", "One-Time Password", Secret(SEED)),))
    search = find_seed_fields(record)
    assert [f.value.reveal() for f in search.fields] == [SEED]


def test_otpauth_prefix_is_found_even_without_a_helpful_label():
    record = make_record(seed=None, extra=(
        KeeperField("text", "notes", Secret(f"otpauth://totp/x?secret={SEED}")),))
    assert find_seed_fields(record).fields


@pytest.mark.parametrize("label", ["Secret Key", "API Key", "Recovery Code",
                                   "Password", "Notes"])
def test_lookalike_labels_are_not_treated_as_seeds(label):
    # Writing an API key into an OTP field would be silent corruption.
    assert not label_suggests_otp(label)
    record = make_record(seed=None, extra=(
        KeeperField("text", label, Secret("not-a-seed-value")),))
    assert not find_seed_fields(record).fields


def test_two_conflicting_custom_seeds_are_a_conflict():
    record = make_record(seed=None, extra=(
        KeeperField("text", "TOTP", Secret(SEED)),
        KeeperField("text", "2FA", Secret(SEED_B)),
    ))
    assert find_seed_fields(record).has_conflict


def test_a_native_field_settles_what_custom_fields_disagree_about():
    record = make_record(seed=SEED, extra=(
        KeeperField("text", "TOTP", Secret(SEED_B)),))
    assert not find_seed_fields(record).has_conflict


def test_identical_custom_seeds_are_not_a_conflict():
    record = make_record(seed=None, extra=(
        KeeperField("text", "TOTP", Secret(SEED)),
        KeeperField("text", "2FA", Secret(SEED)),
    ))
    assert not find_seed_fields(record).has_conflict


def test_normalize_label_folds_case_and_punctuation():
    assert normalize_label("One-Time Password") == normalize_label("one time password")


# -- match_key ----------------------------------------------------------------


def test_match_key_collapses_whitespace_and_case():
    assert match_key("Team  Vault") == match_key("team vault")


def test_match_key_ignores_invisible_formatting_characters():
    # Titles copied from a browser carry a left-to-right mark, which makes two
    # identical-looking titles compare unequal and hides a real match.
    assert match_key("‎Example Service") == match_key("Example Service")


# -- the guard ----------------------------------------------------------------


def test_one_match_would_add():
    match = match_items(make_record(), [make_item()])
    assert match.outcome is Outcome.WOULD_ADD
    assert len(match.items) == 1


def test_no_match_refuses():
    match = match_items(make_record(), [make_item(title="Something Else")])
    assert match.outcome is Outcome.NO_MATCH
    assert not match.items


def test_an_item_that_already_has_a_code_is_left_alone():
    match = match_items(make_record(), [make_item(has_otp=True)])
    assert match.outcome is Outcome.ALREADY_PRESENT


def test_duplicates_in_one_vault_with_one_username_are_all_written():
    # Repeated imports produce copies of one account. Same audience either way.
    items = [make_item("itemidexample00000000000a"),
             make_item("itemidexample00000000000b")]
    match = match_items(make_record(), items)
    assert match.outcome is Outcome.WOULD_ADD
    assert len(match.items) == 2


def test_different_usernames_none_matching_the_record_refuses():
    items = [make_item("itemidexample00000000000a", username="alice@example.com"),
             make_item("itemidexample00000000000b", username="bob@example.com")]
    match = match_items(make_record(username="carol@example.com"), items)
    assert match.outcome is Outcome.AMBIGUOUS


def test_username_breaks_a_tie_within_one_vault():
    items = [make_item("itemidexample00000000000a", username="alice@example.com"),
             make_item("itemidexample00000000000b", username="person@example.com")]
    match = match_items(make_record(username="person@example.com"), items)
    assert match.outcome is Outcome.WOULD_ADD
    assert [i.item_id for i in match.items] == ["itemidexample00000000000b"]


def test_matches_in_two_vaults_refuse_without_corroboration():
    # The two items may be one shared account or two different ones, and nothing
    # 1Password knows separates them. Guessing writes into the wrong audience.
    items = [make_item("itemidexample00000000000a", vault="Team Vault"),
             make_item("itemidexample00000000000b", vault="Other Vault")]
    match = match_items(make_record(), items)
    assert match.outcome is Outcome.AMBIGUOUS


def test_a_shared_folder_naming_exactly_one_vault_settles_it():
    items = [make_item("itemidexample00000000000a", vault="Team Vault"),
             make_item("itemidexample00000000000b", vault="Other Vault")]
    match = match_items(make_record(folders=("Team Vault",)), items)
    assert match.outcome is Outcome.WOULD_ADD
    assert [i.vault for i in match.items] == ["Team Vault"]


def test_a_folder_naming_both_vaults_still_refuses():
    items = [make_item("itemidexample00000000000a", vault="Team Vault"),
             make_item("itemidexample00000000000b", vault="Other Vault")]
    match = match_items(
        make_record(folders=("Team Vault", "Other Vault")), items)
    assert match.outcome is Outcome.AMBIGUOUS


def test_a_folder_naming_neither_vault_still_refuses():
    items = [make_item("itemidexample00000000000a", vault="Team Vault"),
             make_item("itemidexample00000000000b", vault="Other Vault")]
    match = match_items(make_record(folders=("Unrelated",)), items)
    assert match.outcome is Outcome.AMBIGUOUS


def test_folder_names_are_compared_the_way_titles_are():
    items = [make_item("itemidexample00000000000a", vault="Team Vault"),
             make_item("itemidexample00000000000b", vault="Other Vault")]
    match = match_items(make_record(folders=("team  vault",)), items)
    assert match.outcome is Outcome.WOULD_ADD


def test_an_already_finished_item_is_reported_before_ambiguity():
    # Otherwise a permanently-ambiguous finished record trains people to ignore
    # the ambiguous section.
    items = [make_item("itemidexample00000000000a", vault="Team Vault",
                       has_otp=True)]
    match = match_items(make_record(), items)
    assert match.outcome is Outcome.ALREADY_PRESENT


# -- outcomes that need a person ----------------------------------------------


def test_the_needs_attention_set_is_what_the_exit_code_is_built_from():
    for outcome in (Outcome.NO_MATCH, Outcome.AMBIGUOUS, Outcome.FAILED):
        assert outcome in otp_backfill.NEEDS_ATTENTION
    for outcome in (Outcome.ADDED, Outcome.ALREADY_PRESENT):
        assert outcome not in otp_backfill.NEEDS_ATTENTION


def test_match_is_immutable():
    match = Match(outcome=Outcome.WOULD_ADD, reason="x")
    with pytest.raises(Exception):
        match.outcome = Outcome.FAILED


def test_secret_leak_error_exists_for_the_containment_paths():
    assert issubclass(SecretLeakError, RuntimeError)
