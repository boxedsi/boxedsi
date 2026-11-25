"""Rule-based candidates: regexes plus validators, and config-driven hosts, URLs and dictionary terms."""

import bisect
import hashlib
import ipaddress
import math
import re
import string
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import accumulate
from typing import Callable
from urllib.parse import urlsplit

from .validators import iban_ok, inn_ok, luhn_ok, snils_ok

INTERNAL_SUFFIXES = frozenset({"internal", "local", "lan", "corp", "intranet"})
FILE_TLDS = frozenset(
    {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tiff", "css", "js", "ts", "json", "html", "md", "txt", "pdf"}
)
PLACEHOLDER_VALUES = frozenset(
    {"null", "none", "true", "false", "undefined", "changeme", "redacted"}
    | {"скрыт", "скрыто", "скрыта", "скрыты", "нет", "нету", "отсутствует", "отсутствуют", "пусто", "пустой", "неизвестно", "неизвестен"}
    | {"недействителен", "истёк", "истек", "просрочен", "отозван", "удалён", "удален", "утерян", "потерян"}
)
# brackets, quotes and sentence marks around a value: "(скрыт)", "[скрыто]", the guillemets, "нет."
_VALUE_EDGE = ".,;:!?()[]{}<>\N{LEFT-POINTING DOUBLE ANGLE QUOTATION MARK}\N{RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK}"


@dataclass(frozen=True)
class Candidate:
    start: int
    end: int
    kind: str
    text: str
    detector: str


@dataclass(frozen=True)
class Rule:
    name: str
    kind: str
    regex: re.Pattern[str]
    group: int = 0
    validator: Callable[[str], bool] | None = None
    skip_if: re.Pattern[str] | None = None  # skip a match when the 40 characters up to its end fit this pattern, as in a clause number
    # A match of a rule of a later stage is dropped where it overlaps a match of an earlier stage: the rules added later fill the
    # gaps of the older ones and never take a finding from them, whatever their length (see rule_candidates).
    stage: int = 0
    # a match counts only when the text before it, 60 characters at most, ends with this pattern: a word of VAT numbers before a number
    needs: re.Pattern[str] | None = None
    # the validator is asked about the first matches of a text only, and a later match is taken as it is: a check that is slow
    # cannot make a text that is full of such matches slow, and a text of that kind is far more likely right than wrong
    budget: int | None = None
    # a match is dropped where it overlaps a match of this pattern: text that the rule leaves alone
    shield: re.Pattern[str] | None = None
    # the last word on a match, for what its value cannot tell: whether it counts, given the text and the span of the match
    check: Callable[[str, int, int], bool] | None = None
    # the match has the format of a known kind of key (a provider's prefix, a PEM block, a JWT, a card with its checksum): it is
    # one, where the other rules of secrets guess from a name or the look of a value
    known_format: bool = False


# "п. 5.1.2.3" and "section 5.1.2.3" number a clause: a clause word, then a dotted number whose parts are all small. An address
# has a big part ("§ 192.168.1.1"). The abbreviation "п." is lower case, "П." is an initial; "sec." is seconds.
_SMALL = r"(?:30|[12]?\d)"
_CLAUSE_NUMBER = re.compile(
    r"(?i)(?:(?<!\w)(?:(?-i:п{1,2}\.)|ст\.|art\.|(?:пункт|подпункт|раздел)(?:а|е|у|ом|ы|ов|ах)?"
    r"|стать(?:я|и|е|ю|ей|ёй|ях|ям)|clauses?|sections?|articles?)|§)[^\S\r\n]*"
    rf"{_SMALL}(?:\.{_SMALL}){{3}}\Z"
)


def _email_ok(value: str) -> bool:
    return value.rsplit(".", 1)[-1].lower() not in FILE_TLDS


def _phone_ok(value: str) -> bool:
    return 8 <= sum(c.isdigit() for c in value) <= 15


def _ip_ok(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified)


def _card_network_ok(digits: str) -> bool:
    """The number starts like a real card network (cuts Luhn-valid timestamps and IDs)."""
    n, p2, p3, p4 = len(digits), int(digits[:2]), int(digits[:3]), int(digits[:4])
    if digits[0] == "4":
        return n in (13, 16, 19)  # Visa
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:
        return n == 16  # Mastercard
    if p2 in (34, 37):
        return n == 15  # Amex
    if 2200 <= p4 <= 2204:
        return n >= 16  # Mir
    if p4 == 6011 or p2 == 65 or 644 <= p3 <= 649 or 3528 <= p4 <= 3589 or p2 == 62:
        return n >= 16  # Discover, JCB, UnionPay
    if 300 <= p3 <= 305 or p2 in (36, 38, 39):
        return n >= 14  # Diners
    return p2 == 50 or 56 <= p2 <= 69  # Maestro


def _card_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 13 <= len(digits) <= 19 and _card_network_ok(digits) and luhn_ok(digits)


_MARKER_IN_VALUE = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")


def _secret_value_ok(value: str) -> bool:
    if len(set(value)) == 1 or value.lower().strip(_VALUE_EDGE) in PLACEHOLDER_VALUES or _MARKER_IN_VALUE.search(value):
        return False  # a boxed placeholder is already masked, never a new secret
    return not value.startswith(("$", "{", "<", "%"))


# Code that reads a secret, as the plain rules cut it: a known way of reading one, then a call or an index that closes at the end
# of the value or is cut there by a quote ("os.environ[" of os.environ['X'], "config.get(", "get_token()", "sys.argv[1]",
# "getpass(prompt="); or process.env.NAME. The known ways: the environment, the command line, a prompt, a config, settings, secrets,
# a vault or a keyring, and a function whose name says that it gets, reads, loads or fetches (get_token, read_pw, loadSecret). Any
# other call or index is a literal: "Summer(2024)", "Winter.Night(7)" and "Spring[1]" are passwords, whatever the case of the name
# before them and the blanks around "=". A bracket with more after it is part of a password too: "Pa(ss)w0rd", "abc[12]xyz".
_READ_HEAD = (
    r"(?:os\.)?environ(?:\.get)?[(\[]|(?:os\.)?getenv\(|os\.Getenv\(|System\.getenv\(|Deno\.env\.get\(|ENV(?:\.fetch)?[(\[]"
    r"|(?:sys\.)?argv\[|(?:getpass\.)?getpass\(|input\("
    r"|(?:[A-Za-z_]\w{0,63}\.){0,4}(?:config|conf|cfg|settings|secrets|vault|keyring|credentials|creds)(?:\.get\w{0,32})?[(\[]"
    r"|(?:[A-Za-z_]\w{0,63}\.){0,4}(?:get|read|load|fetch)(?:_\w{0,63}|[A-Z]\w{0,63})?\("
)
_CODE_VALUE = re.compile(
    rf"(?:{_READ_HEAD})(?:[^()\[\]\s]{{0,64}}[)\]]|\w{{1,64}}=)?|(?:process|import\.meta)\.env\.[A-Za-z_]\w{{0,63}}"
)
# "pwd" is also the working directory: one of its own names (pwd, PWD, OLDPWD, OLD_PWD) right before the value. A longer name that
# ends in PWD (DB_PWD, MYSQL_PWD) names the password of something.
_PWD_NAME = re.compile(
    r"(?<![A-Za-z0-9_])(?:pwd|PWD|OLDPWD|OLD_PWD)(?:\*\*|__)?[\"'`]?\s{0,8}[:=]\s{0,8}(?:\*\*\s+)?[\"']?\Z"
)
# A line of a .env file: an upper-case name at the start of the line, maybe after "export ", then "=" with no blanks. Its value is
# always a literal ("DB_PASSWORD=read(2024)"): nothing runs there to read a secret.
_ENV_LINE_HEAD = re.compile(r"(?:export[ \t]+)?[A-Z][A-Z0-9_]{0,127}=")


def _not_code(text: str, start: int, end: int) -> bool:
    """A value is a literal unless it is a known way of reading a secret (_CODE_VALUE) outside a line of a .env file."""
    if _ENV_LINE_HEAD.fullmatch(text, text.rfind("\n", max(0, start - 200), start) + 1, start):
        return True
    return not _CODE_VALUE.fullmatch(text, start, end)


def _key_value_check(text: str, start: int, end: int) -> bool:
    return _not_a_working_directory(text, start, end) and _not_code(text, start, end)


def _not_a_working_directory(text: str, start: int, end: int) -> bool:
    """A path of two parts or more after the name pwd is the working directory, not a password; a value after any other name,
    or a path with a random part ("/home/x7Kq9mPzQ2"), is still looked at as a secret."""
    core = text[start:end].strip(_EDGE)
    if not _PATH_LIKE.fullmatch(core) or len([part for part in re.split(r"[\\/]", core) if part]) < 2:
        return True
    return _PWD_NAME.search(text, max(0, start - 120), start) is None


def _plain_word(value: str) -> bool:
    return value.isalpha() and (value.islower() or value.istitle() or value.isupper())


def _secret_shaped(value: str) -> bool:
    """A value after a dash is a secret only when it is no plain word: a digit, a symbol or a capital inside."""
    return not _plain_word(value) and _secret_value_ok(value)


_EDGE = ".,;:()[]{}<>|\N{LEFT-POINTING DOUBLE ANGLE QUOTATION MARK}\N{RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK}*_`\"'"  # around a value: not "!" or "?", a password may end with one
_MAYBE_TYPED = re.compile(r"[\d@:]|^eyJ")  # every e-mail address, number, IP address, IBAN, card and JWT holds one of these


def _typed_value(value: str) -> bool:
    """A value that is wholly an e-mail address, a phone number, an IP address, an IBAN, a card number or a JWT is that, whatever
    stands before it: its kind decides what a policy asks for. "Пароль выслан на почту: ivan@acme.com" holds personal data, and
    called a secret it would be asked less."""
    core = value.strip(_EDGE)
    if not _MAYBE_TYPED.search(core):
        return False
    return any(rule.regex.fullmatch(core) and (rule.validator is None or rule.validator(core)) for rule in _TYPED_RULES)


def _fact_value(value: str) -> bool:
    """A value that is wholly a number, a date, a time, a duration, an address on the net, a path, a handle or the name of an
    algorithm is said of a secret ("Токен доступа действителен до - 2026-12-31", "| Токен | 3600 |", "| Токен | HS256 |"), never
    the secret itself. Eight digits and more are a password or a PIN, not a quantity."""
    core = value.strip(_EDGE)
    if _URL_LIKE.fullmatch(core) or _PATH_LIKE.fullmatch(core) or _HANDLE.fullmatch(core) or _TERM_LIKE.fullmatch(core):
        return True
    if _DATE_LIKE.fullmatch(core) or _UNIT_LIKE.fullmatch(core):
        return True
    return _NUMBER_LIKE.fullmatch(core) is not None and sum(c.isdigit() for c in core) < 8


_TYPE_LIKE = re.compile(r"[^\W\d]\w*(?:\([\w, .]*\)|\[[\w, .]*\]|<[\w, .]*>)+")  # string(64), Optional[str], List<T>, int[]
_LATIN, _CYRILLIC_LETTER = re.compile(r"[A-Za-z]"), re.compile(r"[Ѐ-ӿ]")


_CREDENTIAL_WORDS = frozenset(
    "token secret key pass password passwd pwd auth api bearer jwt access refresh client session private public credential "
    "credentials login oauth hash salt code cookie csrf xsrf signature cert certificate токен секрет ключ пароль доступа".split()
)


def _name_like(value: str) -> bool:
    """A type (string(64), Optional[str]) or a term of words joined by hyphens or underscores: what a table of fields holds. A
    closed bracket group after a name is a type, a bracket in a password is not. The names of environment variables (API_KEY) and
    words of two scripts (Bearer-токен) are terms; so are two words one of which belongs to credentials (access_token,
    client_secret). Other joins, "Summer-Winter" and "correct-horse-battery-staple", are passphrases."""
    if _TYPE_LIKE.fullmatch(value.strip("*_`\"'.,;:")):
        return True
    core = value.strip(_EDGE)
    parts = re.split(r"[-_]", core)
    if len(parts) < 2 or not all(part and _plain_word(part) for part in parts):
        return False
    if all(part.isupper() for part in parts) or (_LATIN.search(core) and _CYRILLIC_LETTER.search(core)):
        return True
    return len(parts) == 2 and any(part.lower() in _CREDENTIAL_WORDS for part in parts)


def _long_value_ok(value: str) -> bool:
    """The value after a name of three or four words, or after a dash that follows one: it must look like a secret."""
    return _secret_shaped(value) and not (_typed_value(value) or _fact_value(value) or _name_like(value))


def _long_quoted_ok(value: str) -> bool:
    return _secret_value_ok(value) and not (_typed_value(value) or _fact_value(value))


def _cell_value_ok(value: str) -> bool:
    """The first word of the cell after a name; marks around it (bold, code, quotes) and a colon after it (a label) are not part of
    it. A table that explains a field holds words, names, types and quantities where a table of logins holds secrets."""
    core = value.strip("*_`\"'").rstrip(":")
    return len(core) >= 4 and _secret_shaped(core) and not (_typed_value(core) or _fact_value(core) or _name_like(core))


# secret-looking names: a known word in any case, or an UPPER_CASE env name with a SECRET/TOKEN/PASSWORD/KEY segment
_SECRET_WORDS = r"pass(?:word|wd)?|pwd|secret|token|(?:api|access|private|secret)[ _\-]?key|auth[_-]?token|client[_-]?secret"
# The name is a keyword and the segments after it. The segments before the keyword do not matter, since the keyword may start
# after any "_"; every repeat is bounded, so no chain of segments can make the search slow.
_SECRET_ENV = r"(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|KEY|APIKEY)(?:_[A-Z0-9]{1,64}){0,8}"
# Russian names, nominative only; a bare "ключ" is no name, as a bare "key" is none. Their left boundary is any letter or
# digit of any script, so a longer word that merely ends in a name is no key.
_SECRET_WORDS_RU = r"пароль|токен|секрет|api[ _\-]?ключ|ключ[ _\-]?api|ключ доступа|(?:секретный|приватный|закрытый) ключ"
# Words between a Russian name and its separator: "Пароль от почты", "Токен доступа", "Токен бота". Up to two are read as a name
# of the plain rules; three or four ("Пароль для входа в систему") are too like a sentence for a plain word to count as the
# value, so they have rules of their own, which want a value that looks like a secret.
_QUALIFIER = r"[ \t]+\w[\w\-]{0,23}"
_QUALIFIERS = rf"(?:{_QUALIFIER}){{0,2}}"
_QUALIFIERS_LONG = rf"(?:{_QUALIFIER}){{3,4}}"
_QUALIFIERS_FAR = rf"(?:{_QUALIFIER}){{0,4}}"
# The separator, with markdown around it: "**Пароль:** x", "**Пароль**: x", "`token`: x".
_SEP = r"(?:\*\*|__)?[\"'`]?\s*[:=]\s*(?:\*\*\s+)?"
# After a Russian name, a plain word followed by more words on the line is a sentence, not a value: "Забыли пароль: нажмите кнопку".
_PROSE = r"(?!(?i:[а-яё]{3,})[,.;:!?]?[ \t]+\S)"
_NAME_START_RU = rf"(?<![^\W_])(?i:{_SECRET_WORDS_RU})"
_NAME_RU = _NAME_START_RU + _QUALIFIERS
_NAME_RU_LONG = _NAME_START_RU + _QUALIFIERS_LONG
_NAME_RU_FAR = _NAME_START_RU + _QUALIFIERS_FAR
_SECRET_NAME = rf"(?:(?<![A-Za-z0-9])(?:(?i:{_SECRET_WORDS})|{_SECRET_ENV}){_SEP}|{_NAME_RU}{_SEP}{_PROSE})"
# A character of a value: not a space or a quote. A comma, "&" or ";" belongs to it unless it ends the value or starts the next
# field: "pa$$,word1" is one value, "password=abcd,user=bob" and "Password=abcd;Database=db" are not.
_VCHAR = r"(?:[^\s\"'&;,]|[&;,](?=[^\s\"'&;,])(?![^\W\d][\w.\-]*[=:]))"
_VALUE = rf"({_VCHAR}{{4,}})"
_DASH = r"[\-\N{EN DASH}\N{EM DASH}]"
# A login and a password in one value: "Логин/пароль: admin/Xk9#mQ2v", "login / password: root / x".
_LOGIN_PASSWORD = rf"(?<![^\W_])(?i:логин|login|user(?:name)?)[ \t]*/[ \t]*(?i:пароль|password|pass){_SEP}([^\s\"'&;,/]+[ \t]*/[ \t]*{_VCHAR}+)"
# URL scheme, at most 32 characters: a scheme of any length makes the search quadratic on long chains such as "a.b.a.b."
_SCHEME = r"[a-z][a-z0-9+.\-]{0,31}"

# What _fact_value takes for a fact: one pattern for each kind, all matched against a whole value.
_UNITS = (
    "ms|s|sec|secs|m|min|mins|h|hr|hrs|d|day|days|w|wk|y|yr|yrs|мс|с|сек|м|мин|ч|час|часа|часов|д|дн|дня|дней|нед|мес|г|год|года|лет"
    "|kb|mb|gb|tb|кб|мб|гб|x|шт|руб|р|usd|eur|rub|\u20bd|\\$|\u20ac|\u00a3"
)
_DATE_LIKE = re.compile(
    r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[T ]\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+\-]\d{2}:?\d{2})?)?"  # 2026-12-31, ...T10:00:00Z
    r"|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"  # 31.12.2026, 12/10/26
    r"|\d{4}-\d{2}|\d{1,2}:\d{2}(?::\d{2})?"  # 2026-12, 10:30
    r"|(?:[QH][1-4]|FY)[-\s]?\d{2,4}|\d{4}[-\s]?[QH][1-4]"  # Q3-2026, H1 2026, FY26, 2026Q3
)
_NUMBER_LIKE = re.compile(r"[+\-\u2212~\u2248]?[vV]?\d+(?:[.,:/\-\u2013]\d+)*(?: ?%)?")  # 3600, 8-20, 24/7, +15%, v2.1.0
_UNIT_LIKE = re.compile(rf"[+\-~]?\d+(?:[.,]\d+)?[ ]?(?i:{_UNITS})\.?")  # 24ч, 15мин, 90d, 100mb
_URL_LIKE = re.compile(rf"(?i:{_SCHEME}://\S+|www\.\S+)")
_SEGMENT = r"[A-Z]?[a-z0-9._\-@%+=]*"  # a part of a path: lower case, or capitalised; "9mayuolQtV" is no part of a path
_PATH_LIKE = re.compile(
    rf"~/{_SEGMENT}(?:/{_SEGMENT})*|\.{{1,2}}/{_SEGMENT}(?:/{_SEGMENT})*"  # ~/.ssh/id_rsa, ./config/secret.key
    rf"|/{_SEGMENT}(?:/{_SEGMENT})+"  # /etc/app/secret.key: two parts at least, a base64 value may start with a slash
    r"|[A-Za-z]:[\\/]\S+"  # C:\Users\app\secret.key
    r"|(?:[a-z]+:)?[a-z][a-z._\-]*(?:/[a-z][a-z._\-]*)+"  # kv/db/admin, vault:kv/app: lower-case words only
)
_HANDLE = re.compile(r"@[A-Za-z][A-Za-z_]{3,31}")  # @BotFather, @admin_support: no digit, "@dmin2026" is a password
_TERM_LIKE = re.compile(  # the names of algorithms and protocols that hold a digit: nobody's password
    r"(?i:oauth\d|saml\d|[23]fa|sha-?\d{1,3}(?:-\d{1,3})?|md[245]|[hrep]s\d{3}|aes-?\d{3}(?:-[a-z]{3})?|rsa-?\d{3,4}|ed25519"
    r"|hmac-sha-?\d{1,3}|crc\d{2}|argon2[a-z]*|pbkdf2|tls-?\d(?:\.\d)?|ssl-?\d|ssh-?\d|ipv[46]|x509|pkcs\d{1,2}|utf-?\d{1,2}"
    r"|base\d{2}|http/?\d(?:\.\d)?)"
)


# --- Passports (stage 1). A passport number has no checksum and a shape that numbers of other kinds have too, so it counts
# only after a word of passports. A Russian internal passport has a series of four digits (two of the region, two of the year the
# blank was made) and a number of six; a foreign one two and seven. Other countries have no common shape: after "passport" a
# number of 6 to 9 capital letters and digits, five of them digits at least. The span is the number, series and label in it too
# ("4510 № 123456"). Runs of blanks are possessive, so a long run of them is read once.
_BLANKS = r"[ \xa0\t]*+"
_SERIES = r"\d{2}[ \xa0\-]?\d{2}"
_NO_LABEL = r"(?:(?i:№|n[o°]?\.?|#|номер)[ \xa0\t.:]*+)"
_BETWEEN = rf"{_BLANKS}[,;/\-]?{_BLANKS}"  # between a series and its number
_PASSPORT_WORD = r"(?i:(?<!\w)(?:(?:загран)?паспорт|passport)[^\W\d_]*+)"
# up to 60 characters with no digit, sentence mark or line break after the word, and one line break: "Паспорт:\n4510 123456"
_PASSPORT_GAP = r"[^\d\n.!?]{0,60}+(?:\n[ \t]*+)?"


def _passport_ok(value: str) -> bool:
    return len({c for c in value if c.isdigit()}) > 1  # "0000 000000" is a placeholder


# --- US social security numbers (stage 1). The Social Security Administration never assigns an area number (the first three
# digits) of 000, 666 or 900-999, a group number (the middle two) of 00 or a serial number (the last four) of 0000: POMS RM
# 10201.035, "Invalid Social Security Numbers", https://secure.ssa.gov/poms.nsf/lnx/0110201035; the same rules are in the SSA's
# "Social Security Number Randomization" FAQ, https://www.ssa.gov/employer/randomizationfaqs.html. With dashes the shape 3-2-4 is
# enough, as in a text of forms; without them (or with spaces) a word of social security numbers must stand within 20 characters.
_SSN_WORD = r"(?i:(?<!\w)(?:SSN|SS#|social[ \-]security(?:[ \-](?:number|no\.?|num\.?|#))?)(?!\w))"
# Numbers of parts, orders and the like have the shape too: with dashes alone a number is no SSN right after such a word, with at
# most a word for "number" between ("Part number", "Order #", "Ref."). Further away the word says nothing of the number:
# "Part-time employee 512-34-7890" is an employee's.
_NOT_SSN = re.compile(
    r"(?i:(?<!\w)(?:parts?|sku|items?|models?|ref(?:erence)?s?|orders?|invoices?|serials?|tracking|артикул\w*|арт"
    r"|заказ(?:а|у|ом|е|ы|ов|ам|ами|ах)?|счёт\w*|накладн\w*)(?!\w)"
    r"(?:[ \t]+(?:numbers?|nos?|num|nr|id|code|номер\w*)(?!\w))?[ \t.:#№]*)\d{3}-\d{2}-\d{4}\Z"
)


def _ssn_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    area, group, serial = int(digits[:3]), digits[3:5], digits[5:]
    return 0 < area < 900 and area != 666 and group != "00" and serial != "0000"


# --- EU VAT numbers (stage 1): a country code and the number. Eight countries have a public checksum, so their numbers are found
# anywhere; the others (and a number of those eight with a wrong checksum) after a word of VAT numbers, as the format alone is
# no proof. AT, BE, DE, IT, NL, PL: the construction rules the member states published, in "Konstruktionsregeln der Umsatzsteuer-
# Identifikationsnummern (UID)", Austrian Federal Ministry of Finance, Nov 2020, https://bmf.gv.at/dam/jcr:d6794f8f-d321-43df-
# 9840-1a841f9bf5dc/BMF_UID_Konstruktionsregeln_Stand_November%202020.pdf. FR: key = (12 + 3 * (SIREN mod 97)) mod 97, "VAT
# identification number" on Wikipedia (worked example FR 83 404833048), a key with a letter has no public rule. ES: the letters of
# the NIF, "Número de identificación fiscal" on Spanish Wikipedia (the control of a legal entity is a letter for the keys N, P, Q,
# R, S and W, a digit for A, B, E and H; Orden EHA/451/2008 defines the keys, not the control); K, L and M (special persons) are
# not read. A VAT number is written with spaces, dots or hyphens in it: they are skipped before the check.
_VAT_D = r"(?:[ .\-]?[0-9])"  # a digit, and a space, dot or hyphen before it
_VAT_CHECKED = {  # what follows the country code
    "AT": rf"[ .\-]?U{_VAT_D}{{8}}",
    "BE": rf"{_VAT_D}{{9,10}}",
    "DE": rf"{_VAT_D}{{9}}",
    "ES": r"[ .\-]?(?:[0-9]{8}[A-Z]|[XYZ][0-9]{7}[A-Z]|[A-HJNP-SUVW][0-9]{7}[0-9A-J])",
    "FR": rf"[ .\-]?[0-9A-HJ-NP-Z]{{2}}{_VAT_D}{{9}}",
    "IT": rf"{_VAT_D}{{11}}",
    "NL": rf"{_VAT_D}{{9}}[ .\-]?B{_VAT_D}{{2}}",
    "PL": rf"{_VAT_D}{{10}}",
}
_VAT_FORMAT_ONLY = {
    "BG": rf"{_VAT_D}{{9,10}}",
    "CY": rf"{_VAT_D}{{8}}[ .\-]?[A-Z]",
    "CZ": rf"{_VAT_D}{{8,10}}",
    "DK": rf"{_VAT_D}{{8}}",
    "EE": rf"{_VAT_D}{{9}}",
    "EL": rf"{_VAT_D}{{9}}",
    "FI": rf"{_VAT_D}{{8}}",
    "HR": rf"{_VAT_D}{{11}}",
    "HU": rf"{_VAT_D}{{8}}",
    "IE": r"[ .\-]?(?:[0-9][A-Z+*][0-9]{5}[A-Z]|[0-9]{7}[A-W][A-I]?)",
    "LT": rf"{_VAT_D}{{9}}(?:{_VAT_D}{{3}})?",
    "LU": rf"{_VAT_D}{{8}}",
    "LV": rf"{_VAT_D}{{11}}",
    "MT": rf"{_VAT_D}{{8}}",
    "PT": rf"{_VAT_D}{{9}}",
    "RO": rf"[ .\-]?[1-9]{_VAT_D}{{5,9}}",
    "SE": rf"{_VAT_D}{{12}}",
    "SI": rf"{_VAT_D}{{8}}",
    "SK": rf"{_VAT_D}{{10}}",
}


def _vat_regex(formats: dict[str, str]) -> re.Pattern[str]:
    return re.compile("(?<![A-Za-z0-9])(?:" + "|".join(f"{country}{rest}" for country, rest in formats.items()) + ")(?![A-Za-z0-9])")


# a word of VAT numbers, then up to 40 characters with no digit or line break, ending where the number starts
_VAT_WORD = re.compile(
    r"(?i:(?<!\w)(?:vat(?:in)?|tva|iva|btw|mwst|ust|uid|umsatzsteuer|tax[ \-]?id|moms|alv|pvm|pvn|dph|dič|áfa|kmkr|ндс|ддс)(?!\w))"
    r"[^\n\d]{0,40}\Z"
)
# The words that stand before a number as its label ("IBAN DE89 ...", "ИНН 7707083893", "SSN 512-34-7890", "VAT ID DE811569869",
# "passport No. 4510 123456", "password hunter22x"): the words of the rules above, IBAN and the names of secrets. A part of a span
# of a name model that holds nothing else is no name (detect._outside).
LABEL_WORD = re.compile(
    r"(?i:iban|inn|tin|snils|ssn|ss|social|security|vat(?:in)?|tva|iva|btw|mwst|ust|uid|umsatzsteuer|tax|id|moms|alv|pvm|pvn|dph|dič|áfa"
    r"|kmkr|number|numbers|no|nr|ндс|ддс|инн|снилс|(?:загран)?паспорт\w*|passport\w*|сери[яи]|номер\w*"
    r"|pass|password|passwd|pwd|secret|token|api|key|access|private|auth|client|пароль|токен|секрет|ключ)"
)
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def _vat_at(n: str) -> bool:  # U and 8 digits; the last is the check
    d = [int(c) for c in n[1:]]
    r = sum(c // 5 + c * 2 % 10 for c in (d[1], d[3], d[5]))
    return (10 - (r + d[0] + d[2] + d[4] + d[6] + 4) % 10) % 10 == d[7]


def _vat_be(n: str) -> bool:  # 10 digits, the first 0 or 1, the last two are 97 - (the first eight mod 97); nine digits lack the 0
    n = n.rjust(10, "0")
    return n[0] in "01" and 97 - int(n[:8]) % 97 == int(n[8:])


def _vat_de(n: str) -> bool:  # ISO 7064 MOD 11,10 over the first eight digits
    p = 10
    for c in n[:8]:
        p = 2 * ((int(c) + p) % 10 or 10) % 11
    return n[0] != "0" and (11 - p) % 10 == int(n[8])


def _vat_es(n: str) -> bool:
    if n[0].isdigit():  # DNI: the letter is the number mod 23
        return n[8] == _DNI_LETTERS[int(n[:8]) % 23]
    if n[0] in "XYZ":  # NIE: the first letter stands for 0, 1, 2
        return n[8] == _DNI_LETTERS[int(str("XYZ".index(n[0])) + n[1:8]) % 23]
    d = [int(c) for c in n[1:8]]  # CIF: the sum of the digits at 2, 4, 6 and of the doubled ones at 1, 3, 5, 7 (their digits added)
    total = d[1] + d[3] + d[5] + sum(c * 2 // 10 + c * 2 % 10 for c in (d[0], d[2], d[4], d[6]))
    digit = (10 - total % 10) % 10
    if n[0] in "ABEH":
        return n[8] == str(digit)
    if n[0] in "NPQRSW":
        return n[8] == "JABCDEFGHI"[digit]
    return n[8] in (str(digit), "JABCDEFGHI"[digit])


def _vat_fr(n: str) -> bool:  # a key of two digits and the SIREN
    return n[:2].isdigit() and int(n[:2]) == (12 + 3 * (int(n[2:]) % 97)) % 97


def _vat_it(n: str) -> bool:  # Luhn over all 11 digits; the office code (digits 8-10) is 1-100, 120, 121, 888 or 999
    office = int(n[7:10])
    return (0 < office <= 100 or office in (120, 121, 888, 999)) and luhn_ok(n)


def _vat_nl(n: str) -> bool:  # 9 digits, B, 2 digits: the modulo 11 test first, then (numbers of 2020 on) the modulo 97 one
    index = int(n[10:])
    a = sum(int(c) * w for c, w in zip(n[:8], range(9, 1, -1))) % 11
    if index > 0 and a != 10 and a == int(n[8]):
        return True
    return 2 <= index <= 98 and int("".join(str(int(c, 36)) for c in "NL" + n)) % 97 == 1  # letters count 10-35


def _vat_pl(n: str) -> bool:
    r = sum(int(c) * w for c, w in zip(n[:9], (6, 5, 7, 2, 3, 4, 5, 6, 7))) % 11
    return r != 10 and r == int(n[9])


_VAT_CHECKS = {"AT": _vat_at, "BE": _vat_be, "DE": _vat_de, "ES": _vat_es, "FR": _vat_fr, "IT": _vat_it, "NL": _vat_nl, "PL": _vat_pl}


def _vat_ok(value: str) -> bool:
    return _VAT_CHECKS[value[:2]](re.sub(r"[ .\-]", "", value[2:]))


# --- Cryptocurrency addresses (stage 1): a main net address of Bitcoin or Ethereum whose own checksum holds.
# Bitcoin base58check: the version byte 0 (P2PKH, "1...") or 5 (P2SH, "3..."), 20 bytes, and the first four bytes of the double
# SHA-256 of both; an address has 25 to 34 characters (https://en.bitcoin.it/wiki/Base58Check_encoding and
# https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses). Bitcoin bech32 (witness version 0, constant 1)
# and bech32m (versions 1-16, constant 0x2bc830a3): BIP-173 and BIP-350, https://github.com/bitcoin/bips; the human-readable part
# is "bc" (test nets are left alone), the string is all lower case or all upper case, 14 to 74 characters, the program 2 to 40
# bytes, 20 or 32 of them for version 0, and the padding of the last character at most 4 bits and all zero. Ethereum: "0x" and 40
# hex digits; when the letters are of both cases the capitals must be those of EIP-55, https://eips.ethereum.org/EIPS/eip-55:
# a letter is a capital when the same position of the Keccak-256 hash of the lower case address, as hex, holds a digit of 8 or
# more. Keccak-256 is the hash of the original submission to the SHA-3 competition, with the padding 0x01 ... 0x80; hashlib has the
# standardised SHA3-256, which pads differently and gives other values. The permutation below follows the Keccak specification.
_B58 = {c: i for i, c in enumerate("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")}
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BECH32M = 0x2BC830A3
_BECH32_HRP_BC = [3, 3, 0, 2, 3]  # the human-readable part "bc", expanded: the high three bits of "b" and "c", 0, the low five bits


def _btc_base58_ok(value: str) -> bool:
    n = 0
    for c in value:
        n = n * 58 + _B58[c]
    try:
        raw = n.to_bytes(25, "big")  # a leading 1 is a zero byte; the length of the string varies, that of the bytes does not
    except OverflowError:
        return False
    return raw[0] == (0 if value[0] == "1" else 5) and hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _bech32_polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _BECH32_GENERATOR[i]
    return chk


def _btc_bech32_ok(value: str) -> bool:
    data = [_BECH32.index(c) for c in value[3:].lower()]
    version = data[0]
    if version > 16 or _bech32_polymod([*_BECH32_HRP_BC, *data]) != (1 if version == 0 else _BECH32M):
        return False
    acc = bits = size = 0  # the program: the data between the version and the checksum, from groups of 5 bits to bytes
    for v in data[1:-6]:
        acc, bits = (acc << 5) | v, bits + 5
        if bits >= 8:
            bits -= 8
            size += 1
            acc &= (1 << bits) - 1
    return bits < 5 and acc == 0 and 2 <= size <= 40 and (version != 0 or size in (20, 32))


_KECCAK_MASK = (1 << 64) - 1


def _keccak_constants() -> tuple[tuple[int, ...], list[int], list[int]]:
    """The round constants (from the shift register of the specification), the rotations and the lane order of the pi step."""
    rounds, r = [], 1
    for _ in range(24):
        rc = 0
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                rc ^= 1 << ((1 << j) - 1)
        rounds.append(rc)
    rotations, lanes, x, y = [], [], 1, 0
    for t in range(24):
        x, y = y, (2 * x + 3 * y) % 5
        rotations.append((t + 1) * (t + 2) // 2 % 64)
        lanes.append(x + 5 * y)
    return tuple(rounds), rotations, lanes


_KECCAK_ROUNDS, _KECCAK_ROTATIONS, _KECCAK_LANES = _keccak_constants()


def _keccak_f(a: list[int]) -> list[int]:
    for rc in _KECCAK_ROUNDS:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[x - 1] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _KECCAK_MASK) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        carried = a[1]
        for lane, r in zip(_KECCAK_LANES, _KECCAK_ROTATIONS):
            carried, a[lane] = a[lane], ((carried << r) | (carried >> (64 - r))) & _KECCAK_MASK
        for row in range(0, 25, 5):
            t = a[row : row + 5]
            for x in range(5):
                a[row + x] = t[x] ^ (~t[(x + 1) % 5] & t[(x + 2) % 5])
        a[0] ^= rc
    return a


def _keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * (-len(padded) % rate)
    padded[-1] |= 0x80
    state = [0] * 25
    for block in range(0, len(padded), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(padded[block + 8 * i : block + 8 * i + 8], "little")
        state = _keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


def _eip55_ok(value: str) -> bool:
    digits = value[2:]
    digest = _keccak256(digits.lower().encode()).hex()
    return all(c.isupper() == (int(h, 16) >= 8) for c, h in zip(digits, digest) if c.isalpha())


# --- Tokens that look random (stage 2: they fill the gaps of every other rule). A token is a run of 20 or more letters, digits,
# "+", "-" and "_"; a slash, dot, colon or "=" cuts it ("=" may close it, as the padding of base64), and hyphens at its edges are
# delimiters ("--boundary--"). It has the shape of a secret when it holds a lower case letter, a capital and a digit; has fewer
# than half of its characters in words of four letters or more (identifiers, slugs and file names are made of them) and fewer than
# one pair in five that goes on in the alphabet (an alphabet constant, 1234...); is no UUID and no hex number; and has an entropy of
# 3.6 bits per character or more. Measured: a random token of 20 characters has an entropy of 3.4 at the least and 3.8 at the 5th
# percentile, of 32 characters 3.9 and 4.3. The shape is not enough, since the ids of services (Stripe, KSUID, ULID, Google Docs),
# model names, class names with digits and base64 data have it too, and a rule of level 0 that flags them blocks prompts and
# masks ids. Measured with 20 characters and 3.6 bits for every token: 18 of 76 hard lines of ordinary text (ids of services,
# model names, urls with ids, base64 in JSON), 13 of 1,314 prompts typed to a coding agent (2,070 tokens) and 70 of 6,000 chunks of
# code (1,172 tokens) held a "secret", where the rules of stage 0 flagged none of the lines. What stands around the token
# decides.
# After a word of credentials on its line (key, token, secret, password, "ключ", ...) the shape is enough. Bare, a token needs 32
# characters (the ids of services have 26 to 28, a key 32 or more; 4.2 bits keeps 94 to 97% of random keys of 32), at most 128
# (a longer run is data, not a key that somebody pastes) and no start that a file in base64 has (eyJ, H4sI, ...). Where the word
# nearest to the token is one of public things (wallet, address, "public key", verification, ...) it is none at all; the private
# key of a wallet is a key. Next to a slash it is a part of a path, unless that path is the one of a webhook, which ends in its
# secret. That leaves 1 of the 76 lines, no prompt and 11 chunks of code (18
# tokens, 3 of them real keys), and 10 of 15 random keys that carry no name (the shape alone found 14, the rules of stage 0
# 3). Only the first 4096 characters of a token are looked at. What the rule leaves alone, a slash and all: a digest with its
# algorithm in front (sha256=..., sha512-..., h1:...), the payload of a data URI, a PEM block that is no private key
# (certificates, public keys) and an SSH public key.
_ENTROPY_MIN = 3.6
_ENTROPY_MIN_BARE = 4.2
_LENGTH_MIN_BARE, _LENGTH_MAX_BARE = 32, 128
_ENTROPY_SAMPLE = 4096
_WORDS = re.compile(r"[A-Z][a-z]{3,}|[a-z]{4,}|[A-Z]{4,}(?![a-z])")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_ENTROPY_SHIELD = re.compile(
    r"-----BEGIN (?![A-Z0-9 ]*PRIVATE)([A-Z0-9][A-Z0-9 ]*[A-Z0-9])-----(?:(?!-----)[\s\S])*?-----END \1-----"
    r"|(?i:data:[^\s,;]{0,127};base64,)[A-Za-z0-9+/_=\-]*"  # a media type is short; a chain of "data:" would make an open bound quadratic
    r"|(?<![A-Za-z0-9])(?i:(?:sha(?:1|224|256|384|512)|md5)[-=:]|h1:)[A-Za-z0-9+/_=\-]+"
    r"|(?<![A-Za-z0-9])(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]+"
)


_NAME_PARTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[А-ЯЁа-яё]+")  # the words of a name: ACCESS_TOKEN, clientSecret
_CREDENTIAL_NAMES = frozenset(
    "key keys apikey token tokens secret secrets password passwd pass passphrase pwd credential credentials creds auth authorization "
    "bearer cookie privkey".split()
)
_CREDENTIAL_STEMS = ("ключ", "токен", "парол", "секрет")
# Public things: a wallet, an address; and the words that turn the credential after them into a public thing ("public key").
_PUBLIC_NOUNS = frozenset("pubkey pbk address addr wallet mint fingerprint thumbprint".split())
_PUBLIC_NOUN_STEMS = ("кошел", "адрес")
_PUBLIC_MODIFIERS = frozenset("public pub verification".split())
_PUBLIC_MODIFIER_STEMS = ("публичн",)
# The start of a file in base64: JSON, gzip, zip and office files, PNG, GIF, PDF, an SSH key, a DER structure (certificates, keys).
_FILE_STARTS = ("eyJ", "H4sI", "UEsDB", "iVBOR", "R0lGO", "JVBER", "AAAAB3", "MII")
# a webhook ends in its secret: .../services/T000/B000/<secret> (Slack), .../api/webhooks/<id>/<secret> (Discord), .../hooks/<secret>
_WEBHOOK_PATH = re.compile(r"(?i)/(?:services/[^/\s]{1,80}/[^/\s]{1,80}|(?:webhooks?|hooks)(?:/[^/\s]{1,80}){0,3})/\Z")


# Parts of a name written as one word (PGPASSWORD, DBPASSWD, VAULTTOKEN), and the words that hold one without being one
_CREDENTIAL_PARTS = ("password", "passwd", "passphrase", "secret", "token", "apikey", "privkey", "credential")
_NOT_CREDENTIAL_WORDS = ("tokenizer",)
# Words and whole names of variables that carry a credential without a word of credentials in them: a DSN holds the key of its
# client (SENTRY_DSN), sshpass reads SSHPASS, the Bitwarden CLI keeps its unlocked session in BW_SESSION.
_CREDENTIAL_ENV_WORDS = frozenset({"dsn"})
_CREDENTIAL_ENV_NAMES = frozenset({"SSHPASS", "BW_SESSION"})


def names_a_credential(name: str) -> bool:
    """Does a name (of an environment variable, of a field) have a word of credentials in it: GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY,
    dbPassword, SSH_AUTH_SOCK, MYSQL_PWD? The words of _context, split the same way; a word that holds a part of credentials
    (PGPASSWORD); and a few known names (_CREDENTIAL_ENV_NAMES)."""
    if name.upper() in _CREDENTIAL_ENV_NAMES:
        return True
    for word in (word.lower() for word in _NAME_PARTS.findall(name)):
        if word in _CREDENTIAL_NAMES or word in _CREDENTIAL_ENV_WORDS or word.startswith(_CREDENTIAL_STEMS):
            return True
        if any(part in word for part in _CREDENTIAL_PARTS) and not word.startswith(_NOT_CREDENTIAL_WORDS):
            return True
    return False


def _context(text: str, start: int) -> str | None:
    """What the words before `start` say of a token: "credentials" (key, token, secret, ...), "public" (wallet, address, ...) or
    nothing. The words are the ones of the 40 characters before it on its line, the names split into their words, and the word
    nearest to the token that says anything decides: a wallet is public, its private key is not. A credential right after
    "public" or "verification" is a public thing too ("public key")."""
    begin = max(0, start - 40)
    line = text.rfind("\n", begin, start)
    words = [word.lower() for word in _NAME_PARTS.findall(text, begin if line < 0 else line + 1, start)]
    for i in range(len(words) - 1, -1, -1):
        word = words[i]
        if word in _PUBLIC_NOUNS or word in _PUBLIC_MODIFIERS or word.startswith(_PUBLIC_NOUN_STEMS + _PUBLIC_MODIFIER_STEMS):
            return "public"
        if word in _CREDENTIAL_NAMES or word.startswith(_CREDENTIAL_STEMS):
            earlier = words[i - 1] if i else ""
            return "public" if earlier in _PUBLIC_MODIFIERS or earlier.startswith(_PUBLIC_MODIFIER_STEMS) else "credentials"
    return None


def _random_token_ok(text: str, start: int, end: int) -> bool:
    value = text[start:end]
    core = value[:_ENTROPY_SAMPLE].rstrip("=")
    n = len(core)
    if n < 20:  # the hyphens at the edges of the run do not count
        return False
    chars = set(core)
    if chars.isdisjoint(string.ascii_lowercase) or chars.isdisjoint(string.ascii_uppercase) or chars.isdisjoint(string.digits):
        return False
    if set(core[2:] if core[:2] in ("0x", "0X") else core) <= _HEX_DIGITS or _UUID.fullmatch(value):  # a hex number is one with its 0x
        return False
    entropy = -sum(c / n * math.log2(c / n) for c in Counter(core).values())
    if entropy < _ENTROPY_MIN or sum(len(word) for word in _WORDS.findall(core)) * 2 >= n:
        return False
    letters = core.lower().encode()
    if sum(abs(a - b) == 1 for a, b in zip(letters, letters[1:])) * 5 >= n - 1:  # one pair in five goes on in the alphabet
        return False
    # it has the shape of a key; whether it is one depends on what stands around it
    before, after = text[start - 1 : start], text[end : end + 1]
    webhook = before == "/" and _WEBHOOK_PATH.search(text, max(0, start - 120), start) is not None
    if (before == "/" or after == "/") and not webhook:
        return False
    context = "credentials" if webhook else _context(text, start)
    if context:
        return context == "credentials"
    return _LENGTH_MIN_BARE <= n <= _LENGTH_MAX_BARE and entropy >= _ENTROPY_MIN_BARE and not value.startswith(_FILE_STARTS)


# --- the rules

RULES: tuple[Rule, ...] = (
    Rule(
        "rule:email",
        "EMAIL",
        re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,254}+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![\w-])"),
        validator=_email_ok,
    ),
    Rule("rule:phone-intl", "PHONE", re.compile(r"(?<![\w+])\+\d{1,3}(?:[ \-().]*\d){6,14}(?!\d)"), validator=_phone_ok),
    Rule("rule:phone-ru", "PHONE", re.compile(r"(?<!\d)8[ \-]?\(\d{3}\)[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}(?!\d)")),
    Rule(
        "rule:ipv4",
        "IP",
        re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)"),
        validator=_ip_ok,
        skip_if=_CLAUSE_NUMBER,
    ),
    Rule("rule:ipv6", "IP", re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"), validator=_ip_ok),
    Rule("rule:aws-key", "SECRET", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), known_format=True),
    Rule("rule:github-token", "SECRET", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"), known_format=True),
    Rule("rule:anthropic-key", "SECRET", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), known_format=True),
    Rule("rule:openai-key", "SECRET", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), known_format=True),
    Rule("rule:slack-token", "SECRET", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), known_format=True),
    Rule("rule:google-key", "SECRET", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"), known_format=True),
    Rule("rule:stripe-key", "SECRET", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"), known_format=True),
    Rule("rule:gitlab-token", "SECRET", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), known_format=True),
    Rule("rule:digitalocean-token", "SECRET", re.compile(r"\bdop_v1_[0-9a-f]{64}\b"), known_format=True),
    Rule("rule:shopify-token", "SECRET", re.compile(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"), known_format=True),
    Rule("rule:bearer", "SECRET", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{8,}=*)"), group=1),
    Rule(
        "rule:key-value",
        "SECRET",
        re.compile(_SECRET_NAME + r"[\"']?" + _VALUE),
        group=1,
        validator=_secret_value_ok,
        check=_key_value_check,
    ),
    Rule(
        "rule:key-value-quoted",
        "SECRET",
        re.compile(_SECRET_NAME + r"([\"'])((?:(?!\1)[^\n]){4,200})\1"),
        group=2,
        validator=_secret_value_ok,
        check=_not_a_working_directory,
    ),
    Rule(
        "rule:key-value-long",
        "SECRET",
        re.compile(rf"{_NAME_RU_LONG}{_SEP}{_PROSE}[\"']?" + _VALUE),
        group=1,
        validator=_long_value_ok,
    ),
    Rule(
        "rule:key-value-quoted-long",
        "SECRET",
        re.compile(rf"{_NAME_RU_LONG}{_SEP}{_PROSE}" + r"([\"'])((?:(?!\1)[^\n]){4,200})\1"),
        group=2,
        validator=_long_quoted_ok,
    ),
    Rule(
        "rule:key-dash",
        "SECRET",
        re.compile(rf"{_NAME_RU}(?:\*\*|__)?[ \t]+{_DASH}[ \t]+(?:\*\*[ \t]+)?[\"']?" + _VALUE),
        group=1,
        validator=_secret_shaped,
    ),
    Rule(
        "rule:key-dash-long",
        "SECRET",
        re.compile(rf"{_NAME_RU_LONG}(?:\*\*|__)?[ \t]+{_DASH}[ \t]+(?:\*\*[ \t]+)?[\"']?" + _VALUE),
        group=1,
        validator=_long_value_ok,
    ),
    Rule("rule:login-password", "SECRET", re.compile(_LOGIN_PASSWORD), group=1, validator=_secret_value_ok),
    Rule("rule:telegram-bot-token", "SECRET", re.compile(r"(?<!\d)\d{8,10}:[A-Za-z0-9_\-]{35}(?![A-Za-z0-9_\-])"), known_format=True),
    Rule("rule:url-credentials", "SECRET", re.compile(rf"(?i)\b{_SCHEME}://([^/\s:@]+:[^/\s@]+)@"), group=1),
    Rule(
        "rule:private-key",
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----(?:(?!-----)[\s\S])*?-----END \1PRIVATE KEY-----"),
        known_format=True,
    ),
    Rule("rule:jwt", "JWT", re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), known_format=True),
    Rule("rule:card", "CARD", re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)"), validator=_card_ok, known_format=True),
    Rule(
        "rule:iban",
        "IBAN",
        re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Z0-9])"),
        validator=iban_ok,
    ),
    Rule("rule:inn", "INN", re.compile(r"(?i)(?<!\w)(?:ИНН|INN|TIN)\s*(?:[:№#=]\s*)?(\d{12}|\d{10})(?!\d)"), group=1, validator=inn_ok),
    Rule("rule:snils", "SNILS", re.compile(r"(?<!\d)\d{3}-\d{3}-\d{3}[ \-]\d{2}(?!\d)"), validator=snils_ok),
    Rule("rule:snils-plain", "SNILS", re.compile(r"(?i)(?<!\w)(?:СНИЛС|SNILS)\s*(?:[:№#=]\s*)?(\d{11})(?!\d)"), group=1, validator=snils_ok),
    # --- stage 1: they fill the gaps of the rules above
    Rule(
        "rule:passport",
        "PASSPORT",
        re.compile(rf"{_PASSPORT_WORD}{_PASSPORT_GAP}({_SERIES}{_BETWEEN}{_NO_LABEL}?\d{{6}})(?!\d)"),
        group=1,
        validator=_passport_ok,
        stage=1,
    ),
    Rule(
        "rule:passport-foreign",
        "PASSPORT",
        re.compile(rf"{_PASSPORT_WORD}{_PASSPORT_GAP}(\d{{2}}[ \xa0\-]?\d{{7}})(?!\d)"),
        group=1,
        validator=_passport_ok,
        stage=1,
    ),
    Rule(
        "rule:passport-series",
        "PASSPORT",
        re.compile(rf"(?i:(?<!\w)сери[яи])[ \xa0\t.:]*+({_SERIES}{_BETWEEN}{_NO_LABEL}\d{{6}})(?!\d)"),
        group=1,
        validator=_passport_ok,
        stage=1,
    ),
    Rule(
        "rule:passport-other",
        "PASSPORT",
        re.compile(
            r"(?i:(?<!\w)(?:passport|reisepass|passeport|pasaporte|passaporto|pasaport)[^\W\d_]*+)"
            r"(?:[ \t]++(?i:nr|no|num|number|numero|número|id)\b\.?|[ \t]*+(?:n°|№|#))?[ \t:=#.\-]*+"
            r"(?<!\w)((?=(?:[A-Z]*\d){5})[A-Z0-9]{6,9})(?!\w)"
        ),
        group=1,
        validator=_passport_ok,
        stage=1,
    ),
    Rule(
        "rule:ssn",
        "SSN",
        re.compile(r"(?<![\w\-])(?<!\d\.)(\d{3}-\d{2}-\d{4})(?![\w\-]|\.\d)"),
        group=1,
        validator=_ssn_ok,
        skip_if=_NOT_SSN,
        stage=1,
    ),
    Rule(
        "rule:ssn-word",
        "SSN",
        re.compile(rf"{_SSN_WORD}[^\d\n]{{0,20}}+(?<![\w\-])(\d{{3}}[ \-]?\d{{2}}[ \-]?\d{{4}})(?![\w\-])"),
        group=1,
        validator=_ssn_ok,
        stage=1,
    ),
    Rule("rule:vat-id", "VAT_ID", _vat_regex(_VAT_CHECKED), validator=_vat_ok, stage=1),
    Rule("rule:vat-id-word", "VAT_ID", _vat_regex(_VAT_CHECKED | _VAT_FORMAT_ONLY), needs=_VAT_WORD, stage=1),
    Rule(
        "rule:btc-base58",
        "CRYPTO_ADDR",
        re.compile(r"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{24,33}(?![A-Za-z0-9])"),
        validator=_btc_base58_ok,
        stage=1,
    ),
    Rule(
        "rule:btc-bech32",
        "CRYPTO_ADDR",
        re.compile(r"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{11,71}|BC1[AC-HJ-NP-Z02-9]{11,71})(?![A-Za-z0-9])"),
        validator=_btc_bech32_ok,
        stage=1,
    ),
    Rule("rule:eth", "CRYPTO_ADDR", re.compile(r"(?<![A-Za-z0-9])0x(?:[0-9a-f]{40}|[0-9A-F]{40})(?![A-Za-z0-9])"), stage=1),
    Rule(
        "rule:eth-checksum",
        "CRYPTO_ADDR",
        re.compile(r"(?<![A-Za-z0-9])0x(?=[0-9A-F]*[a-f])(?=[0-9a-f]*[A-F])[0-9A-Fa-f]{40}(?![A-Za-z0-9])"),
        validator=_eip55_ok,
        budget=256,  # a Keccak-256 in Python takes 0.2 ms
        stage=1,
    ),
    Rule(
        "rule:high-entropy",
        "SECRET",
        # hyphens at the edges are delimiters ("--boundary--"), so the token starts and ends with another character; it is cut
        # out of the run by an atomic group, which gives back the trailing hyphens once and for all
        re.compile(
            r"(?<![A-Za-z0-9+_\-])-*+(?=[A-Za-z0-9+_\-]{20})((?>[A-Za-z0-9+_][A-Za-z0-9+_\-]*[A-Za-z0-9+_])={0,2})-*+"
            r"(?![A-Za-z0-9+_=]|\.[A-Za-z0-9]|://)"
        ),
        group=1,
        check=_random_token_ok,
        shield=_ENTROPY_SHIELD,
        stage=2,
    ),
)
KNOWN_FORMATS = frozenset(rule.name for rule in RULES if rule.known_format)  # the detectors whose finding is a key of a known format
_KNOWN_RULES = tuple(rule for rule in RULES if rule.known_format)


def is_known_format(detector: str, value: str) -> bool:
    """Is a finding a key of a known format? Its rule says so, or the value alone is wholly one: a JWT after "Bearer" is the
    finding of the rule of headers, and still a JWT."""
    if detector in KNOWN_FORMATS:
        return True
    return any(rule.regex.fullmatch(value) and (rule.validator is None or rule.validator(value)) for rule in _KNOWN_RULES)
_TYPED_RULES = tuple(r for r in RULES if r.kind in ("EMAIL", "PHONE", "IP", "IBAN", "CARD", "JWT"))  # see _typed_value

_HOST = re.compile(r"(?<![\w.\-@/])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9\-]{0,62}(?![\w\-])")
_URL = re.compile(rf"(?i)\b{_SCHEME}://[^\s\"'<>`]+")
_URL_TRAILING = ".,;:!?\"')]}>"


def is_internal_host(host: str, internal_domains: list[str]) -> bool:
    h = host.lower().rstrip(".")
    if h.rsplit(".", 1)[-1] in INTERNAL_SUFFIXES:
        return True
    return any(h == d.lower() or h.endswith("." + d.lower()) for d in internal_domains)


# A Markdown or TSV table names a secret in one cell and holds it in another, in one of two layouts. A row names it in a cell and holds
# it in the next ("| Пароль | Xk9#mQ2v |", "Пароль<TAB>Xk9#mQ2v"). Or a header cell names it and the cells under it, to the end of
# the table, hold the secrets ("| Логин | Пароль |" over "| admin | Xk9#mQ2v |"). A "|" or a tab ends a cell only here: after a name
# anywhere else it is a shell pipe, an alternation or the column of a struct. A name is a cell of its own (bold, code or quotes
# around it are fine); a value is the first word of a cell and must look like a secret, as after a dash. A row reads Russian names
# only, like the dash: a table of English parameters (`| token | string(64) |`) is full of values that look like secrets. A header
# reads English names too, being a header of columns that hold values, which are tested the same strict way. Cell by cell, so a long
# run of blanks or separators is read once.
_CELL_SEPARATOR = re.compile(r"[|\t]")
_CELL_MARKS = r"[*_`\"']{0,2}"
_HEADER_NAME = re.compile(  # the cell of a name; a note in brackets may follow it: "Пароль (временный)"
    rf"\s*{_CELL_MARKS}(?:(?P<ru>{_NAME_RU_FAR})|(?:[\w\-]+[ \t]+){{0,2}}(?i:{_SECRET_WORDS})|(?:[A-Z0-9]+_)*{_SECRET_ENV})"
    rf"(?:[ \t]*\([^()|\t]{{0,40}}\))?{_CELL_MARKS}:?{_CELL_MARKS}\s*"
)


def names_a_secret(cell: str) -> bool:
    """Does the cell name a secret, as the header of a column does ("password", "API key", "DB_TOKEN", "Пароль (временный)")? The
    same test the text tables use; a sheet or a CSV file masks every value under such a header."""
    return _HEADER_NAME.fullmatch(cell) is not None


_NOT_A_LABEL = re.compile(r"[\d#$@!%^=+~<>{}\[\]\\]")  # a header holds labels, a row of a list holds a value: "Xk9#mQ2v", "hunter22x"
_CELL_WORD = re.compile(rf"\s*[\"']?({_VCHAR}{{4,}})")  # a value as the plain rules read it: "pa$$,word1" is one, "abcd, user" is not


def _cells(row: str) -> list[tuple[int, int]]:
    """The cells of a row as spans of it, cut at every pipe and tab; the outer pipes of a Markdown row make no cell."""
    cuts = [-1, *(m.start() for m in _CELL_SEPARATOR.finditer(row)), len(row)]
    cells = [(a + 1, b) for a, b in zip(cuts, cuts[1:])]
    outline = row.strip()
    if outline.startswith("|"):
        cells = cells[1:]
    if outline.endswith("|") and cells:
        cells = cells[:-1]
    return cells


def _holds_labels(row: str, cells: list[tuple[int, int]], named: list[int]) -> bool:
    """Every cell of a header row but the ones that name a secret is a label."""
    names = set(named)
    return all(k in names or not _NOT_A_LABEL.search(row, a, b) for k, (a, b) in enumerate(cells))


def _is_dashes(row: str) -> bool:
    """The row of dashes under the header of a Markdown table: |---|:---:|"""
    outline = row.strip()
    return "-" in outline and "|" in outline and not outline.strip("|:- \t")


def cell_candidates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    rows = text.split("\n")
    base = 0
    columns: list[int] = []  # the columns of the table being read that its header named
    divider = ""  # "|" or a tab: what separates the cells of that table
    for i, row in enumerate(rows):
        here = "|" if "|" in row else "\t" if "\t" in row else ""
        if not here:
            columns = []
        else:
            cells = _cells(row)
            named, russian = [], []  # the cells that name a secret, and those among them that do so in Russian
            for k, (a, b) in enumerate(cells):
                if name := _HEADER_NAME.fullmatch(row, a, b):
                    named.append(k)
                    if name.group("ru"):
                        russian.append(k)
            tabular = row.lstrip().startswith("|")
            for k in russian:
                a, b = cells[k]
                if k + 1 == len(cells):
                    continue
                if row[b] == "|" and not (tabular or row[b - 1] in " \t" or row[b + 1 : b + 2] in (" ", "\t")):
                    continue  # a pipe with no table around it, no outer pipe and no space beside it: an alternation, not a cell
                word = _CELL_WORD.match(row, cells[k + 1][0], cells[k + 1][1])
                if word and _cell_value_ok(word.group(1)):
                    start, end = word.span(1)
                    out.append(Candidate(base + start, base + end, "SECRET", word.group(1), "rule:key-cell"))
            following = rows[i + 1] if i + 1 < len(rows) else ""
            if named and (_is_dashes(following) if here == "|" else "\t" in following) and _holds_labels(row, cells, named):
                columns, divider = named, here  # a header: the table starts under it
            elif columns and here == divider and not _is_dashes(row):
                for k in columns:
                    if k >= len(cells):
                        break
                    word = _CELL_WORD.match(row, cells[k][0], cells[k][1])
                    if word and _cell_value_ok(word.group(1)):
                        start, end = word.span(1)
                        out.append(Candidate(base + start, base + end, "SECRET", word.group(1), "rule:key-cell"))
            elif here != divider:
                columns = []
        base += len(row) + 1
    return out


class _Spans:
    """Whether a span overlaps any of some spans: the starts are sorted once, and a question is a bisect and a look at the
    furthest end among the spans that start before the end asked about."""

    def __init__(self, spans: Iterable[tuple[int, int]]) -> None:
        ordered = sorted(spans)
        self._starts = [start for start, _ in ordered]
        self._reach = list(accumulate((end for _, end in ordered), max))

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect.bisect_left(self._starts, end)  # the spans that start before the end
        return i > 0 and self._reach[i - 1] > start


def _matches(rule: Rule, text: str) -> Iterator[Candidate]:
    asked = 0
    for m in rule.regex.finditer(text):
        value = m.group(rule.group)
        if rule.validator and (rule.budget is None or asked < rule.budget):
            asked += 1
            if not rule.validator(value):
                continue
        start, end = m.span(rule.group)
        if rule.skip_if and rule.skip_if.search(text, max(0, start - 40), end):
            continue
        if rule.needs and not rule.needs.search(text, max(0, start - 60), start):
            continue
        if rule.check and not rule.check(text, start, end):
            continue
        yield Candidate(start, end, rule.kind, value, rule.name)


def rule_candidates(text: str, taken: Iterable[Candidate] = ()) -> list[Candidate]:
    """The matches of every rule, stage by stage. Stage 0 holds the base rules and the cells of tables; a later stage
    sees what the earlier ones found and drops its own matches that overlap them, so the longest-first resolution of detect() can
    never pick a new match over an old one: nothing an older rule finds is lost to a rule added later. `taken` are the findings
    of the config (hosts, URLs, dictionary terms) that count as an earlier stage for the later ones: a rule added later would cut
    a dictionary term at the hyphen of a token ("Acme Project-x7Kq...") if it could."""
    out: list[Candidate] = []
    for stage in sorted({0, *(rule.stage for rule in RULES)}):
        found: list[Candidate] = []
        for rule in RULES:
            if rule.stage != stage:
                continue
            matches = list(_matches(rule, text))
            if matches and rule.shield:  # looked for only when the rule found something
                shielded = _Spans(m.span() for m in rule.shield.finditer(text))
                matches = [c for c in matches if not shielded.overlaps(c.start, c.end)]
            found += matches
        if stage == 0:
            found += cell_candidates(text)
        else:
            seen = _Spans((c.start, c.end) for c in [*out, *taken])
            found = [c for c in found if not seen.overlaps(c.start, c.end)]
        out += found
    return out


def host_url_candidates(text: str, internal_domains: list[str]) -> tuple[list[Candidate], list[tuple[int, int]]]:
    """Internal hosts and URLs, plus the authority spans of URLs with credentials (no email may start there)."""
    out: list[Candidate] = []
    authority_spans: list[tuple[int, int]] = []
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(_URL_TRAILING)
        start, end = m.start(), m.start() + len(url)
        try:
            parts = urlsplit(url)
            hostname = parts.hostname
        except ValueError:  # malformed, e.g. an unclosed "[": hosts inside are still found by _HOST below
            continue
        if "@" in parts.netloc:
            a_start = start + url.index("//") + 2
            authority_spans.append((a_start, a_start + len(parts.netloc)))
        if hostname and is_internal_host(hostname, internal_domains):
            out.append(Candidate(start, end, "URL", url, "rule:internal-url"))
    for m in _HOST.finditer(text):
        if text[m.end() : m.end() + 1] == "(":
            continue
        if is_internal_host(m.group(0), internal_domains):
            out.append(Candidate(m.start(), m.end(), "HOST", m.group(0), "rule:internal-host"))
    return out, authority_spans


def dictionary_candidates(text: str, dictionary: dict[str, str]) -> list[Candidate]:
    out = []
    for term, kind in dictionary.items():
        if not term:
            continue
        for m in re.finditer(r"(?<!\w)" + re.escape(term) + r"(?!\w)", text, re.IGNORECASE):
            out.append(Candidate(m.start(), m.end(), kind.upper(), m.group(0), "dict"))
    return out
