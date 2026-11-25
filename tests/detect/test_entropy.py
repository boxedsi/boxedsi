"""The high-entropy SECRET rule: a token that looks random, in a place no older rule looked at.

A token is a run of letters, digits, "+", "-" and "_" (a slash, dot, colon or "=" cuts it; "=" may close it as base64 padding). It
counts when it holds a lower case letter, a capital and a digit, it is no UUID, no hash in hex, no run of a character set (an
alphabet, 1234...), fewer than half of its characters are words of four letters or more (identifiers, slugs and file names are),
and its Shannon entropy is high enough. How high, and how long the token must be, depends on what stands before it. After a word
of credentials on the same line (key, token, secret, password, "ключ", ...) 20 characters and 3.6 bits per character are enough;
bare, 32 characters and 4.2 bits are wanted, no more than 128 characters (a longer run is data), and no start that is the start of
a file in base64 (eyJ, H4sI, ...). A word of public things before it (public, wallet, address, verification, ...) takes it out;
so does a slash right before or after it, except in the path of a webhook. Digests with their algorithm (sha256=..., sha512-...,
h1:...), the payload of a data URI, public PEM blocks and SSH public keys are left alone. The rule fills gaps: whatever an older
rule finds stays as it was. The numbers are measured: a random token of 20 characters has an entropy of 3.4 at the least and 3.8
at the 5th percentile, one of 32 characters 3.9 and 4.3; the ids of services (Stripe, KSUID, ULID, Docs, Figma), model names and
class names with digits of 20 to 31 characters have an entropy of 4.0 to 4.4 as well, so only the length, or a word before the
token, tells them from a key."""

import base64
import json
import random
import string
from pathlib import Path

import pytest

from boxed.detect import DetectConfig, detect

ROOT = Path(__file__).resolve().parents[2]
ALPHABETS = {
    "base62": string.ascii_letters + string.digits,
    "base64": string.ascii_letters + string.digits + "+",
    "base64url": string.ascii_letters + string.digits + "-_",
}


def found(text, level=0, config=None):
    return [(d.kind, d.text) for d in detect(text, level=level, config=config)]


def token(rng, alphabet, n):
    return "".join(rng.choice(alphabet) for _ in range(n))


_PEM_RNG = random.Random("pem")
PEM_BODY = "\n".join(token(_PEM_RNG, ALPHABETS["base64"], 64) for _ in range(4))  # four lines of a block, 64 characters each


# --- what it finds


SECRET32 = "6wzGkWlEB5FL81rqxvse1c1A2dj3tUGk"  # 32 characters, 4.7 bits
SECRET24 = "LlUetPbmH3XdVPJfv4G27PGN"  # 24 characters, 4.3 bits: as long as the ids of services
SHORT_ONES = [SECRET24, "xyzab-Yaa5lE4aN0nTHcmC4mse", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]  # 24, 26 and 26 characters (the Basic credentials of RFC 7617)


@pytest.mark.parametrize(
    "secret",
    [
        SECRET32,
        "rIlVEeNO6heZyk_-og_xTFbha0jKwvh7wH0nDMxE",
        "npm_dJIjRXRCPWAJNqsZi4n1VXi8RHIQJyUelGEp",
        "wXElaupmePDHARbE3KNDPDdVSgsJ6ejozbBlfNBtONT",
    ],
)
def test_a_random_looking_token_of_32_characters_or_more(secret):
    assert found(f"The temporary code is {secret}, do not share it.") == [("SECRET", secret)]
    assert found(secret) == [("SECRET", secret)]


@pytest.mark.parametrize("secret", SHORT_ONES)
@pytest.mark.parametrize(
    "before",
    [
        "my token ",
        "the key is ",
        "the secret: ",
        "Authorization: Basic ",
        "the credentials are ",
        "clientSecret ",
        "ACCESS_TOKEN ",
        "passphrase for the vpn - ",
        "the token for the staging server is ",  # a word of credentials, a few others between, on one line
        "ключ ",
        "Токен доступа - ",
        "Пароль от почты: ",
    ],
)
def test_a_token_of_20_to_31_characters_after_a_word_of_credentials(before, secret):
    assert found(f"{before}{secret}") == [("SECRET", secret)]
    assert found(f"{before}{secret}, thanks") == [("SECRET", secret)]


@pytest.mark.parametrize("secret", SHORT_ONES)
@pytest.mark.parametrize(
    "text",
    [
        "{t}",  # the ids of services have the same length and entropy: nothing tells them from a key
        "here: {t}",
        "use {t} to log in",
        'value "{t}" end',
        "the code is {t}",
        "my token{gap}{t}",  # the word is 40 characters away or more
        "my token\n{t}",  # on the line before
        "{t} is my token",  # after it
        "tokenizer: {t}",  # a word that starts with one
        "Monkey {t}",  # a word that ends with one
        "the keyboard {t}",
    ],
)
def test_a_token_of_20_to_31_characters_with_no_word_of_credentials_before_it_is_no_secret(text, secret):
    assert found(text.format(t=secret, gap=" " * 45)) == []


@pytest.mark.parametrize(
    "text,value",
    [
        ('{"id": "' + SECRET32 + '"}', SECRET32),
        ("mykey=" + SECRET32, SECRET32),
        ("https://example.com/reset?code=" + SECRET32 + "&x=1", SECRET32),
        ("Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ("see " + SECRET32 + ".\nNext line", SECRET32),
        (SECRET32 + "==", SECRET32 + "=="),
        ("host." + SECRET32 + " end", SECRET32),
        ("(" + SECRET32 + ")", SECRET32),
        ("--" + SECRET32 + "--", SECRET32),  # hyphens at the edges are delimiters, as in a MIME boundary
        ("-" + SECRET32, SECRET32),
        (SECRET32 + "-- and more", SECRET32),
        ("--" + SECRET32 + "==--", SECRET32 + "=="),
        ("rIlVEeNO6heZyk_-og_xTFbha0jKwvh7wH0nDMxE", "rIlVEeNO6heZyk_-og_xTFbha0jKwvh7wH0nDMxE"),  # hyphens inside stay
    ],
)
def test_the_span_is_the_token(text, value):
    assert found(text) == [("SECRET", value)]


def test_it_is_a_secret_at_every_level():
    for level in (0, 1, 2, 3, 4):
        assert ("SECRET", SECRET32) in found("code " + SECRET32, level=level)


# the path of a webhook ends in its secret: a slash before the token is no reason to leave it alone there
WEBHOOKS = [
    "https://hooks.slack.com/services/T0123ABCD/B0123ABCD/{t}",
    "https://discord.com/api/webhooks/123456789012345678/{t}",
    "https://chat.example.com/hooks/{t}",
    "https://hooks.zapier.com/hooks/catch/123456/{t}/",
]


@pytest.mark.parametrize("url", WEBHOOKS)
@pytest.mark.parametrize("secret", [SECRET24, SECRET32])
def test_the_secret_in_the_path_of_a_webhook(url, secret):
    assert found(url.format(t=secret)) == [("SECRET", secret)]


@pytest.mark.parametrize(
    "text",
    [
        "https://docs.google.com/document/d/{t}/edit",  # ids of documents, files, deploys: a path of a url
        "https://example.com/{t}",
        "/var/lib/{t}/data",
        "dweb:/ipfs/{t}",
        "my token https://example.com/api/{t}",  # a word of credentials does not change that
        "token {t}/index.js",
        "https://example.com/services/{t}",  # a word of webhooks is no webhook
        "https://example.com/hooks/a/b/c/d/{t}",  # four parts between are too many
    ],
)
def test_a_token_next_to_a_slash_is_no_secret(text):
    assert found(text.format(t=SECRET32)) == []
    assert found(text.format(t=SECRET24)) == []


def test_a_slash_cuts_a_token():
    # base64 has a slash, so a secret that holds one is cut into pieces that stand next to it: they are found no more
    piece_a, piece_b = "JdcAFzRTCJx0HBwHWBpw9w", "p1uhK5AxDN10TjrEaRQMys"
    assert found(f"{piece_a}/{piece_b}") == []
    assert found("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") == []


def test_a_token_longer_than_128_characters_is_data_unless_a_word_of_credentials_stands_before_it():
    blob = token(random.Random("blob"), ALPHABETS["base64"], 200)
    assert found(f"Attachment (base64): {blob}") == []
    assert found(f"token {blob}") == [("SECRET", blob)]
    assert found(f"here: {blob[:128]}") == [("SECRET", blob[:128])]


@pytest.mark.parametrize("start", ["eyJ", "H4sI", "UEsDB", "iVBOR", "R0lGO", "JVBER", "AAAAB3", "MII"])
def test_a_token_that_starts_as_a_file_in_base64_is_data_unless_a_word_of_credentials_stands_before_it(start):
    value = (start + SECRET32 + "Xr7Qp9Zt")[:40]
    assert found(f"Here is the response: {value} - can you read it?") == []
    assert found(f"credentials: {value}") == [("SECRET", value)]


@pytest.mark.parametrize(
    "before",
    [
        "чей кошелек ",
        "wallet `",
        "const MINT = '",
        "the address is ",
        "send to the Solana address: ",
        "public key: ",
        "pubkey=",
        "Reality pubkey (pbk) | `",
        "&pbk=",
        "google-site-verification=",
        "TXT record for the verification of the domain: ",
        "publicKey: ",
        "pub key ",
        "verification token ",
        "the public wallet address ",
        "the token address ",
        "api key for the wallet ",
    ],
)
@pytest.mark.parametrize("secret", [SECRET24, SECRET32, "H3rNFpUAV5HPYUhPNBYjNyUDeYYnHpjmQr7MdRVSCzTQ"])
def test_a_token_after_a_word_of_public_things_is_no_secret(before, secret):
    assert found(f"{before}{secret}") == []


@pytest.mark.parametrize(
    "before",
    [
        "wallet private key ",
        "wallet secret ",
        "the wallet token is ",
        "address and token ",
        "public address, private key ",
        "public wallet - password ",
        "mint authority secret key ",
    ],
)
@pytest.mark.parametrize("secret", [SECRET24, SECRET32])
def test_the_word_nearest_to_the_token_decides_between_credentials_and_public_things(before, secret):
    """A wallet is public, its private key is not: "public" turns the key word after it into a public thing ("public key"), a
    wallet or an address before it does not."""
    assert found(f"{before}{secret}") == [("SECRET", secret)]


def test_the_recall_on_random_tokens():
    """Measured with 400 random tokens of each length and alphabet (seeded); the thresholds sit under what was measured. Bare, a
    token has to be 32 characters long; after a word of credentials 20 are enough."""
    bare = {32: 0.90, 40: 0.92, 64: 0.95}
    after_a_word = {20: 0.82, 24: 0.87, 32: 0.90}
    for name, alphabet in ALPHABETS.items():
        rng = random.Random(name)
        for n, expected in bare.items():
            tokens = [token(rng, alphabet, n) for _ in range(400)]
            hits = sum(found(f"code {t} end") == [("SECRET", t)] for t in tokens)
            assert hits / len(tokens) >= expected, (name, n, hits)
        for n, expected in after_a_word.items():
            tokens = [token(rng, alphabet, n) for _ in range(400)]
            hits = sum(found(f"my token {t} end") == [("SECRET", t)] for t in tokens)
            assert hits / len(tokens) >= expected, (name, n, hits)


# --- what it leaves alone


@pytest.mark.parametrize(
    "text",
    [
        "getUserAccountPermissionsForTenant2",  # identifiers
        "ThisIsAVeryLongCamelCaseIdentifier2Name",
        "test_get_text_plain_utf8_base64_recoverable_bad_CTE_data",
        "my-super-long-article-title-for-2026-update-v2-Final",
        "Donaudampfschifffahrtsgesellschaftskapitaen",
        "TestPositionalsNargsNoneZeroOrMore1",
        "SHA256WithRSAEncryptionAndSomethingElse",
        "/Users/dev/projects/app/.claude/worktrees/agent-3f9c2e71b0d4a85c6",  # paths
        "/private/tmp/claude-501/-Users-dev-projects/5b2f7c10-8e4d-4a9b-b3c6-2d71e0f94a58/scratchpad",
        "C:\\Users\\Administrator\\AppData\\Local\\Programs\\Python\\Python313\\python.exe",
        "src/boxed/detect/Patterns2.py and tests/detect/test_Linear3.py",
        "https://github.com/anthropics/claude-code/issues/12345?utm_source=newsletter&utm_campaign=Spring2026Launch",  # URLs
        "https://example.com/blog/2026/10/how-to-write-good-commit-messages-in-large-teams",
        "www.example-company-with-a-long-name-2026.co.uk/products/item-4711",
        "meta-llama/Llama-3-8B-Instruct and CohereForAI/c4ai-command-r-v01",
        "123e4567-e89b-12d3-a456-426614174000",  # UUIDs, in any case
        "123E4567-E89B-12D3-A456-426614174000",
        "123e4567-E89B-12d3-A456-426614174000",
        "d41d8cd98f00b204e9800998ecf8427e",  # hashes in hex
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "AbCdEf0123456789aBcDeF0123456789AbCdEf01",  # hex of both cases
        "0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",  # a hex number
        "0xa9fB57dbA1eeA9bc3E660a909D838d718C397aA3B561a6F7901E0e82974856A7",
        "image@sha256:3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",  # alphabets and runs
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "Password123Password123Password123",  # a short pattern repeated
        "Aa1Aa1Aa1Aa1Aa1Aa1Aa1Aa1",
        "aB3xK9mQ2vLpaB3xK9mQ2vLpaB3xK9mQ2vLp",
        "12345678901234567890123",  # numbers and words
        "LlUetPbmH3XdVPJfv4G",  # 19 characters
        "lluetpbmh3xdvpjfv4g27pgn",  # no capital
        "LLUETPBMH3XDVPJFV4G27PGN",  # no lower case
        "LlUetPbmHxXdVPJfvgGaPGNb",  # no digit
        "LlUetPbmH3XdVPJfv4G27PGN.png",  # a file or a name on the net
        "LlUetPbmH3XdVPJfv4G27PGN.example.com",
        "LlUetPbmH3XdVPJfv4G27PGN://",
    ],
)
def test_ordinary_text_is_no_secret(text):
    assert [kind for kind, _ in found(text)] == [], text


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_WALLET = token(random.Random("wallet"), _BASE58, 44)
_JSON_IN_BASE64 = base64.b64encode(json.dumps({"user": "alice", "iat": 1700000000, "roles": ["admin", "dev"]}).encode()).decode()


@pytest.mark.parametrize(
    "text",
    [
        # the ids of services: 26 to 28 characters, a third to a half of them digits, the entropy of a key
        "stripe event evt_1MqZs3L2eZvKYlo2C5Z6Xk9a and payment pi_3MtwBwLkdIwHu7ix28a3tqPa",
        "customer cus_NffrFeUfNV2Hib subscription sub_1MowQVLkdIwHu7ixeRlqHVzs",
        "KSUID 0ujsswThIGTUYm2K8FjOOfXtY1K for the user",
        "ULID 01ARZ3NDEKTSV4RRFFQ69G5FAV created",
        "nanoid: V1StGXR8_Z5jdHi6B-myT",
        "https://docs.google.com/spreadsheets/d/1kQ9mZxR3vT7bN2cLpW8dY4fH6jS1aE5gU0iO9tVwXyZ/edit#gid=0",
        "https://www.figma.com/file/Zk7aP2mQ9xLrT4vB8nC1yD/Design-System?node-id=12%3A34",
        "https://my-app-3kd9f8s7d-acme.vercel.app/_next/static/chunks/pages/index-9f2a1b3c4d5e6f70.js",
        "arn:aws:iam::123456789012:role/service-role/MyLambdaExecutionRole-ab12CD34",
        "Slack message https://acme.slack.com/archives/C0123ABCDEF/p1698765432123456",
        "ls -la /var/lib/docker/overlay2/3f9aB2c4D5e6F7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2/diff",
        # model names, images, class names and identifiers with digits
        "Use Qwen/Qwen3-VL-235B-A22B-Instruct for the vision part.",
        "model: deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
        "ollama pull hf.co/unsloth/Qwen3-Coder-480B-A35B-Instruct-GGUF:Q4_K_M",
        "huggingface-cli download nvidia/Llama-3_1-Nemotron-70B-Instruct-HF --local-dir models/",
        "model = 'claude-opus-4-5-20251101'  # or gpt-5.1-codex-max, gemini-2.5-pro-preview-06-05",
        "FROM nvidia/cuda:12.4.1-cudnn-devel-ubuntu22.04 AS base",
        "kubectl logs web-7d9f8b6c5d-x2k9q -n prod-eu-west-1",
        "from transformers import TFAutoModelForSequenceClassification2, AutoTokenizer",
        "export const PROMETHEUS_REMOTE_WRITE_RECEIVER_V2_ENABLED = true;",
        "Window.getComputedStyle(document.querySelector('.Layer_a1B2c3__item-9xKd'))",
        ".PhotoView__Photo-3f9aB2 .EmojiKeyboardPanel__Item--active7Zk { color: red }",
        "Файл Dogovor_Ivanov_2026-10-24_FINAL_v3.docx лежит в папке Dokumenty/Dogovora/2026",
        "Скрипт запускается так: python3 sdelat_otchet_po_prodazham.py --kvartal=3 --god=2026 --format=xlsx",
        "Таблица VneshniyKlientIdentifikator2026 содержит 120 строк",
        # data: base64 of a file, a wallet, the pieces of a long run
        f"Here is the response body: {_JSON_IN_BASE64}  - can you decode it?",
        f"чей кошелек {_WALLET} ?",
        "Attachment (base64): " + token(random.Random("attachment"), ALPHABETS["base64"], 300),
        "test fixture: const SAMPLE = \"" + token(random.Random("fixture"), ALPHABETS["base64"], 160) + "\";",
    ],
)
def test_the_ids_of_services_model_names_and_data_are_no_secret(text):
    assert [kind for kind, _ in found(text)] == [], text


@pytest.mark.parametrize(
    "text",
    [
        "sha256=aDlRQ_IamqKbgjIWjHGJKvXsTxriUpVxzSUKccnjegM",  # a wheel's RECORD
        'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"',
        '"integrity": "sha512-aB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPqRsTuVwXyZ/aB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPqRsTuVwXyZ+AbCdEf0123456789xYzQ==",',
        "github.com/foo/bar v1.2.3 h1:aB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPqRsTuVwXy=",
        "src: url(data:font/woff2;base64,d09GMgABAAAAAAhYAAsAAAAAEdAAAAgLAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABmQXAAAAAA/aB3xK9mQ2vLp7RtN4aB8c)",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
        "data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,UEsDBBQABgAIAAAAIQBi7p1oXgEAAJAEAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAAC",  # a long media type
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCaB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPqRsTuVwXyZ0123456789/aB3xK9mQ2vLp7 me@host",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host",
        "-----BEGIN CERTIFICATE-----\n" + PEM_BODY + "\n-----END CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----\n" + PEM_BODY + "\n-----END PUBLIC KEY-----",
        "-----BEGIN CERTIFICATE REQUEST-----\n" + PEM_BODY + "\n-----END CERTIFICATE REQUEST-----",
    ],
)
def test_digests_data_uris_public_keys_and_certificates_are_no_secret(text):
    assert [kind for kind, _ in found(text)] == [], text


def test_a_private_key_block_stays_one_private_key():
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAaB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPqRsTuVwXyZ\naB3xK9mQ2vLp7RtN4aB8cDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeF\n-----END RSA PRIVATE KEY-----"
    assert found(f"key:\n{block}\ndone") == [("PRIVATE_KEY", block)]


# --- what the older rules keep


def test_the_older_rules_keep_what_they_find():
    secret = "LlUetPbmH3XdVPJfv4G27PGN"
    assert [(d.kind, d.detector) for d in detect(f"password={secret}", level=0)] == [("SECRET", "rule:key-value")]
    assert [(d.kind, d.detector) for d in detect(f"| Пароль | {secret} |", level=0)] == [("SECRET", "rule:key-cell")]
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert found(f"token {jwt}") == [("JWT", jwt)]
    assert found(f"{secret}@example.com", level=1) == [("EMAIL", f"{secret}@example.com")]
    assert found(f"{secret}4111111111111111") == [("CARD", "4111111111111111")]  # the card is found; the token around it is not
    telegram = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"
    assert found(telegram) == [("SECRET", telegram)]
    assert [d.detector for d in detect(telegram, level=0)] == ["rule:telegram-bot-token"]


def test_an_internal_url_that_starts_inside_a_token_stays_a_url():
    # a scheme may hold "-" and "+", so the older URL rule starts up to 32 characters before "://", inside a long token: the token
    # must not be taken over it
    config = DetectConfig(internal_domains=["acme.local"])
    text = "rIlVEeNO6heZyk_-og_xTFbha0jKwvh7wH0nDMxE-ftp://a.acme.local/x"
    got = found(text, level=2, config=config)
    assert [kind for kind, _ in got] == ["URL"] and got[0][1].endswith("://a.acme.local/x"), got


# --- the repository's own text is ordinary text

@pytest.mark.parametrize("pattern", ["src/**/*.py", "docs/guide/*.md", "bench/*.py", "scripts/*.py"])
def test_the_repositorys_own_files_hold_no_high_entropy_token(pattern):
    hits = []
    for path in sorted(ROOT.glob(pattern)):
        text = path.read_text(encoding="utf-8")
        hits += [(path.name, d.text) for d in detect(text, level=0) if d.detector == "rule:high-entropy"]
    assert hits == []
