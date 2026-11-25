import pytest

from boxed.detect import KINDS_BY_LEVEL, DetectConfig, Detection, detect


def found(text, level=2, config=None):
    return [(d.kind, d.text) for d in detect(text, level=level, config=config)]


def kinds(text, level=2, config=None):
    return [d.kind for d in detect(text, level=level, config=config)]


# EMAIL


def test_email():
    assert found("contact ivan.petrov@acme.com today") == [("EMAIL", "ivan.petrov@acme.com")]


def test_email_negative_retina_asset():
    assert kinds("icon@2x.png and logo@3x.webp") == []


def test_email_right_after_a_percent_sign_is_found():
    # a list of addresses with the comma percent-encoded: both are addresses, the second one starts after the "%"
    result = found("to=a@b.io%2Cc@d.io")
    assert [kind for kind, _ in result] == ["EMAIL", "EMAIL"]
    assert result[0][1] == "a@b.io" and result[1][1].endswith("c@d.io")


# PHONE


@pytest.mark.parametrize("phone", ["+7 (912) 345-67-89", "+44 20 7946 0958"])
def test_phone(phone):
    assert found(f"call {phone} now") == [("PHONE", phone)]


def test_phone_negative_date():
    assert "PHONE" not in kinds("released 2026-10-20 at 10:00")


# IP


def test_ip():
    assert found("client 203.0.113.7 connected") == [("IP", "203.0.113.7")]


def test_ipv6():
    assert found("from 2001:db8::8a2e:370:7334 ok") == [("IP", "2001:db8::8a2e:370:7334")]


def test_ip_negative_loopback_and_times():
    assert kinds("bind 127.0.0.1 and 0.0.0.0 at 12:34:56") == []


@pytest.mark.parametrize(
    "text",
    [
        "согласно п. 5.1.2.3 договора",
        "см. п.5.1.2.3",
        "см. п.п. 5.1.2.3",
        "пп. 5.1.2.3 приложения",
        "Пункт 5.1.2.3 применяется",
        "в пункте 5.1.2.3 указано",
        "раздел 1.2.3.4 описывает",
        "в разделе 1.2.3.4",
        "по ст. 10.2.3.4 закона",
        "статья 10.2.3.4",
        "согласно статье 10.2.3.4",
        "see clause 5.1.2.3 below",
        "Section 5.1.2.3 applies",
        "per § 5.1.2.3",
        "§5.1.2.3",
        "under art. 5.1.2.3 of the act",
        "п.\xa05.1.2.3",
    ],
)
def test_dotted_quad_right_after_a_clause_word_is_not_an_ip(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "text,ip",
    [
        ("ping 8.8.8.8 now", "8.8.8.8"),
        ("dns 1.1.1.1", "1.1.1.1"),
        ("в разделе сети укажите 8.8.8.8", "8.8.8.8"),  # words between the clause word and the number
        ("стоп. 8.8.8.8", "8.8.8.8"),  # "п." ends a longer word
        ("пост. 1.1.1.1", "1.1.1.1"),  # "ст." ends a longer word
        ("Section\n10.0.0.1 gateway", "10.0.0.1"),  # a line break separates them
        ("Section 5.1.2.3 and 8.8.8.8", "8.8.8.8"),  # only the number right after the word
    ],
)
def test_ip_away_from_clause_words_is_still_found(text, ip):
    assert found(text) == [("IP", ip)]


@pytest.mark.parametrize(
    "text,ip",
    [
        ("retry in 16 sec. 10.181.52.204 not responding", "10.181.52.204"),  # "sec." is seconds
        ("Иванов И. П. 10.0.0.5 подключился", "10.0.0.5"),  # "П." is an initial
        ("§ 192.168.1.1", "192.168.1.1"),  # a part above 30 is an address, not a clause number
        ("по п. 192.168.0.1", "192.168.0.1"),
        ("пункт 10.2.3.40", "10.2.3.40"),
    ],
)
def test_a_look_alike_of_a_clause_word_or_number_does_not_hide_an_ip(text, ip):
    assert found(text) == [("IP", ip)]


# SECRET


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJ012345-xyz",
        "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
        "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
        "AIzaSyA-1234567890abcdefghijklmnopqrstu",
    ],
)
def test_known_key_formats(secret):
    assert found(f"key {secret} end") == [("SECRET", secret)]


@pytest.mark.parametrize(
    "line,value",
    [
        ("password=hunter2&user=bob", "hunter2"),
        ('"token": "abc123def456"', "abc123def456"),
        ("secret: s3cr3tvalue", "s3cr3tvalue"),
        ("api_key = 'XyZ987abc'", "XyZ987abc"),
        ("Authorization: Bearer eyabc.def-ghi_123", "eyabc.def-ghi_123"),
    ],
)
def test_key_value_secret_masks_value_only(line, value):
    assert found(line) == [("SECRET", value)]


def test_url_credentials():
    assert found("clone https://u:p4ss@github.com/acme/repo") == [("SECRET", "u:p4ss")]


def test_secret_negatives():
    assert kinds("password field is required, token_count=5, password=****") == []


@pytest.mark.parametrize(
    "line,value",
    [
        ("pwd = hunter2x", "hunter2x"),  # pwd still names a password when its value is no path
        ("PWD=/home/user/x7Kq9mPzQ2", "/home/user/x7Kq9mPzQ2"),  # a random part is no part of a path
        ("pwd = /tmpXk9#mQ2v", "/tmpXk9#mQ2v"),  # one part only
        ("password = /home/user/project", "/home/user/project"),  # only pwd is also the working directory
        ("password = Pa(ss)w0rd", "Pa(ss)w0rd"),  # brackets inside a password are no call
        ("password = Xk9(mQ2v", "Xk9(mQ2v"),
        ("token = abc[12]xyz", "abc[12]xyz"),
        ("secret = os.environ", "os.environ"),  # no call or index: a dotted word may be a password
    ],
)
def test_a_secret_of_the_shape_of_a_path_or_a_call_is_still_found(line, value):
    assert found(line) == [("SECRET", value)]


# Only the names of the working directory itself (pwd, PWD, OLDPWD, OLD_PWD) take a path for the working directory: a name that merely
# ends in PWD names the password of something, and a password of words and slashes is still one.
@pytest.mark.parametrize("name", ["pwd", "PWD", "OLDPWD", "OLD_PWD"])
def test_a_path_after_the_name_of_the_working_directory_is_no_secret(name):
    assert found(f"{name}=/home/user/project") == []


@pytest.mark.parametrize("name", ["DB_PWD", "db_pwd", "MYSQL_PWD", "ADMIN_PWD_PROD"])
def test_a_path_shaped_value_after_a_compound_pwd_name_is_a_secret(name):
    assert found(f"{name}=correct/horse/battery") == [("SECRET", "correct/horse/battery")]
    assert found(f"{name}=/home/user/project") == [("SECRET", "/home/user/project")]


# A value after a name of a secret is a secret, whatever the case of the name and the blanks around "=", and also when it has the
# shape of a call or an index ("Summer(2024)" is a password). Only a known way of reading a secret is code: the environment, the
# command line, a prompt, a config or a vault, or a function whose name says it gets, reads, loads or fetches something.
@pytest.mark.parametrize(
    "text,value",
    [
        ("DB_PASSWORD=Summer(2024)", "Summer(2024)"),
        ("DB_HOST=localhost\nDB_PASSWORD=Qwerty()\nDB_USER=app\n", "Qwerty()"),
        ("export API_TOKEN=Spring[1]", "Spring[1]"),
        ("SECRET_KEY=Winter.Night(7)  # the old one", "Winter.Night(7)"),
        ("password = Summer(2024)", "Summer(2024)"),
        ("PASSWORD = Summer(2024)", "Summer(2024)"),
        ("Password=Summer(2024)", "Summer(2024)"),
        ("db_password =Qwerty()", "Qwerty()"),
        ("  api_token\t=  Spring[1]", "Spring[1]"),
        ("secret_key = Winter.Night(7)", "Winter.Night(7)"),
    ],
)
def test_a_call_shaped_value_is_a_secret_in_any_case_and_with_any_blanks(text, value):
    assert found(text) == [("SECRET", value)]


@pytest.mark.parametrize(
    "text",
    [
        "token=get_token()",
        "password = sys.argv[1]",
        "  db_password=read_pw()",
        "password = os.environ['DB_PASSWORD']",
        'PASSWORD = os.environ.get("DB_PASSWORD")',
        "password = os.getenv('DB_PASSWORD')",
        "password = getpass()",
        "password = getpass.getpass(prompt='pw: ')",
        "secret = config.get('secret')",
        "api_key = settings['api_key']",
        "token = process.env.API_TOKEN",
        "password = keyring.get_password('app', 'me')",
        "password = loadSecret()",
    ],
)
def test_a_known_way_of_reading_a_secret_is_no_secret(text):
    assert found(text) == []


# A line of a .env file (an upper-case name at the start of the line, maybe after "export ", and "=" with no blanks) holds a literal:
# nothing reads a secret there, so a value in the shape of a reading is still the password. In code the reading stays code.
@pytest.mark.parametrize(
    "text,value",
    [
        ("DB_PASSWORD=read(2024)", "read(2024)"),
        ("PASSWORD=config[prod]", "config[prod]"),
        ("export API_TOKEN=settings[0]", "settings[0]"),
        ("DB_HOST=localhost\nDB_PASSWORD=get_pw()\n", "get_pw()"),
    ],
)
def test_a_value_on_a_line_of_an_env_file_is_a_secret_even_in_the_shape_of_a_reading(text, value):
    assert found(text) == [("SECRET", value)]


@pytest.mark.parametrize(
    "text",
    ['token = os.environ["X"]', "password = get_password()", 'key = config.get("k")', "    PASSWORD = read(2024)", "x = 1; PASSWORD=read(2024)"],
)
def test_the_same_reading_in_code_is_no_secret(text):
    assert found(text) == []


# PRIVATE_KEY


def test_private_key_block():
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----"
    assert found(f"key:\n{block}\ndone") == [("PRIVATE_KEY", block)]


def test_public_key_not_private():
    assert kinds("-----BEGIN PUBLIC KEY-----\nMIIBIjAN\n-----END PUBLIC KEY-----") == []


def test_encrypted_private_key_block_with_headers():
    block = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123ABCD\n\nMIIEow\n-----END RSA PRIVATE KEY-----"
    assert found(f"key:\n{block}\ndone") == [("PRIVATE_KEY", block)]


def test_an_unclosed_block_does_not_hide_the_next_closed_one():
    closed = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"
    assert found(f"-----BEGIN PRIVATE KEY-----\ncut off\n{closed}") == [("PRIVATE_KEY", closed)]


# JWT


def test_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcDEF123_-xyz"
    assert found(f"auth {jwt} ok") == [("JWT", jwt)]


def test_jwt_negative_short():
    assert kinds("eyJ.not.a") == []


@pytest.mark.parametrize("before", ["session=", "/auth/", '"jwt":"', "(", "jwt: ", "\n"])
def test_jwt_after_a_separator(before):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcDEF123_-xyz"
    assert found(f"{before}{jwt}") == [("JWT", jwt)]


# CARD, IBAN, INN, SNILS


def test_card():
    assert found("paid with 4111 1111 1111 1111") == [("CARD", "4111 1111 1111 1111")]


def test_card_negative_bad_luhn():
    assert kinds("order 4111 1111 1111 1112") == []


def test_card_negative_ms_timestamp():
    # 1792464731000 passes Luhn but no card network starts with 17
    assert kinds("ts 1792464731000 done") == []


def test_iban():
    assert found("IBAN DE89 3704 0044 0532 0130 00 ok") == [("IBAN", "DE89 3704 0044 0532 0130 00")]


def test_iban_negative():
    assert kinds("ref DE89370400440532013001") == []


def test_inn_with_context():
    assert found("ИНН 7707083893, КПП 770701001") == [("INN", "7707083893")]


@pytest.mark.parametrize("gap", ["", " ", ": ", " № ", "   =   ", "\n#"])
def test_inn_and_snils_across_separators(gap):
    assert found(f"ИНН{gap}7707083893") == [("INN", "7707083893")]
    assert found(f"СНИЛС{gap}11223344595") == [("SNILS", "11223344595")]


def test_inn_negative_keyword_inside_word():
    assert kinds("Martin 7707083893 done") == []


def test_inn_negative_bad_checksum():
    assert "INN" not in kinds("ИНН 7707083894")


def test_inn_negative_timestamp_without_context():
    # 1792464737 passes the INN checksum but is a unix timestamp
    assert kinds("ts=1792464737 event=login") == []


def test_snils():
    assert found("СНИЛС 112-233-445 95") == [("SNILS", "112-233-445 95")]


def test_snils_negative():
    assert kinds("СНИЛС 112-233-445 96") == []


# HOST and URL


def test_internal_host_from_config():
    cfg = DetectConfig(internal_domains=["corp.acme.io"])
    assert found("connect to db1.corp.acme.io:5432", config=cfg) == [("HOST", "db1.corp.acme.io")]


@pytest.mark.parametrize("host", ["api.internal", "printer.local", "nas.lan", "git.corp"])
def test_internal_host_by_suffix(host):
    assert found(f"ping {host} done") == [("HOST", host)]


def test_public_host_not_masked():
    assert kinds("see github.com and pypi.org") == []


def test_code_attribute_call_not_host():
    assert kinds("data = threading.local()") == []


def test_internal_url_whole():
    cfg = DetectConfig(internal_domains=["corp.acme.io"])
    url = "https://wiki.corp.acme.io/page?id=1"
    assert found(f"docs: {url}.", config=cfg) == [("URL", url)]


def test_malformed_url_does_not_crash():
    cfg = DetectConfig(internal_domains=["corp.acme.io"])
    text = "broken http://[::1 and http://[db.corp.acme.io/x end"
    assert ("HOST", "db.corp.acme.io") in found(text, config=cfg)


def test_public_url_not_masked():
    assert kinds("docs: https://github.com/acme/repo") == []


def test_credentials_are_still_found_after_a_long_chain():
    text = "a.b." * 50_000 + "https://u:p4ss@github.com/acme/repo"
    assert found(text) == [("SECRET", "u:p4ss")]


def test_a_scheme_of_32_characters_is_still_a_url():
    cfg = DetectConfig(internal_domains=["corp.acme.io"])
    url = "x" * 32 + "://wiki.corp.acme.io/page"
    assert found(f"see {url} now", config=cfg) == [("URL", url)]


# dictionary, allow, levels


def test_dictionary_level_2_only():
    cfg = DetectConfig(dictionary={"Acme Corp": "CLIENT"})
    assert found("Contract with Acme Corp and ACME CORP signed", config=cfg) == [
        ("CLIENT", "Acme Corp"),
        ("CLIENT", "ACME CORP"),
    ]
    assert found("Contract with Acme Corp signed", level=1, config=cfg) == []


def test_allow_suppresses():
    cfg = DetectConfig(allow={"ivan.petrov@acme.com"})
    assert found("ivan.petrov@acme.com and anna@acme.com", config=cfg) == [("EMAIL", "anna@acme.com")]


def test_level_0_only_secrets():
    text = "ivan.petrov@acme.com AKIAIOSFODNN7EXAMPLE"
    assert found(text, level=0) == [("SECRET", "AKIAIOSFODNN7EXAMPLE")]


def test_kinds_by_level_nested():
    assert KINDS_BY_LEVEL[0] < KINDS_BY_LEVEL[1] < KINDS_BY_LEVEL[2]
    assert {"SECRET", "PRIVATE_KEY", "JWT", "CARD"} == set(KINDS_BY_LEVEL[0])


# structure of results


def test_results_sorted_and_non_overlapping():
    cfg = DetectConfig(internal_domains=["corp.acme.io"])
    text = "bob@db.corp.acme.io then 203.0.113.7 then https://u:p4ss@db.corp.acme.io/x"
    ds = detect(text, config=cfg)
    assert [d.kind for d in ds] == ["EMAIL", "IP", "URL"]
    assert all(a.end <= b.start for a, b in zip(ds, ds[1:]))
    assert all(text[d.start : d.end] == d.text for d in ds)
    assert all(isinstance(d, Detection) and d.detector for d in ds)


def test_marker_is_not_a_secret_value():
    assert kinds("DB_PASSWORD=[SECRET_1] and token: [SECRET_2]") == []


@pytest.mark.parametrize(
    "line,value",
    [
        ("SECRET_KEY=abc123xyz789", "abc123xyz789"),
        ("SECRET_KEY_BASE=deadbeefcafe1234", "deadbeefcafe1234"),
        ("APP_KEY=base64:abcd1234efgh=", "base64:abcd1234efgh="),
        ("ENCRYPTION_KEY=0123456789abcdef", "0123456789abcdef"),
        ("STRIPE_SECRET_KEY=sk_test_51Habc123def456ghi", "sk_test_51Habc123def456ghi"),
        ("password = 'correct horse battery'", "correct horse battery"),
        ("MY_APP_DB_PROD_EU_ADMIN_PASSWORD=abc123xyz789", "abc123xyz789"),
        ("my_DB_TOKEN=abc123xyz789", "abc123xyz789"),
        ("SECRET_A_B_C_D_E_F_G=abc123xyz789", "abc123xyz789"),
        ("export AWS_SECRET_ACCESS_KEY=abcd1234efgh5678", "abcd1234efgh5678"),
    ],
)
def test_more_secret_shapes(line, value):
    assert found(line) == [("SECRET", value)]


def test_key_names_that_are_not_secrets():
    assert kinds("KEYBOARD=us MONKEY=1 primary_key = id") == []


# SECRET: Russian names in key-value lines


@pytest.mark.parametrize(
    "line,value",
    [
        ("Пароль: Xk9#mQ2v", "Xk9#mQ2v"),
        ("пароль=Xk9#mQ2v&логин=bob", "Xk9#mQ2v"),
        ("ПАРОЛЬ: Xk9#mQ2v", "Xk9#mQ2v"),
        ("Токен: tk-9f8e7d6c5b4a", "tk-9f8e7d6c5b4a"),
        ("API-ключ: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("API ключ = 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("Ключ API: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("Ключ доступа: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("Секретный ключ: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("Приватный ключ: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("Секрет: s3cr3tvalue", "s3cr3tvalue"),
        ("Логин: admin, пароль: Xk9#mQ2v, роль: оператор", "Xk9#mQ2v"),
        ("(пароль: Xk9#mQ2v, логин: bob)", "Xk9#mQ2v"),
        ('"Пароль": "Xk9#mQ2v"', "Xk9#mQ2v"),
        ("Пароль: 'мой длинный пароль'", "мой длинный пароль"),
        ("Пароль: Привет2026", "Привет2026"),
        ("Ваш пароль:\nXk9#mQ2v", "Xk9#mQ2v"),
    ],
)
def test_russian_key_value_secret_masks_value_only(line, value):
    assert found(line) == [("SECRET", value)]


@pytest.mark.parametrize(
    "text",
    [
        "Ключ от сейфа лежит у директора, а пароль знает только администратор.",
        "Введите пароль и нажмите Войти. Токен обновится сам.",
        "Пароль:",
        "Пароль: \n",
        "Пароль: нет",
        "Пароль: ******",
        "Пароль: [SECRET_1]",
        "Пароль: ${DB_PASSWORD}",
        "Ключ: значение",
        "суперпароль: Xk9#mQ2v",
    ],
)
def test_russian_prose_and_non_values_are_not_secrets(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "Забыли пароль: нажмите кнопку Восстановить",
        "Пароль: должен содержать не менее восьми символов",
        "Пароль: Введите ваш пароль",
        "Токен: истёк, обновите страницу",
        "Секрет: никому не рассказывайте",
        "Ключ API: получите в личном кабинете",
        "Токен доступа: действует час",
        "Пароль:\nЛогин: bob",
        "Пароль:\nПовторите пароль:",
    ],
)
def test_a_plain_word_followed_by_more_words_is_prose_not_a_secret(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "Пароль: скрыт",
        "Пароль: скрыто",
        "Пароль: скрыто.",
        "Токен: отсутствует",
        "Токен: отсутствуют.",
        "Пароль: нету",
        "Пароль: нет",
        "Пароль: пусто",
        "Пароль: неизвестно",
        "Секрет: неизвестен",
        "Токен: недействителен",
        "Токен: истёк.",
        "Пароль: (скрыт)",
        "Пароль: [скрыто]",
        "Пароль: \N{LEFT-POINTING DOUBLE ANGLE QUOTATION MARK}скрыт\N{RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK}",
    ],
)
def test_russian_placeholders_are_not_secrets(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "line,value",
    [
        ("Пароль: Xk9#mQ2v и логин admin", "Xk9#mQ2v"),
        ("Пароль: qwerty и дальше", "qwerty"),  # a Latin word is a possible password
        ("Пароль: привет2026 и далее", "привет2026"),  # digits make it a password
        ("Пароль: привет", "привет"),  # a word alone is not told from a password
        ("Токен: нажмите123 кнопку", "нажмите123"),
    ],
)
def test_real_looking_secrets_next_to_words_are_still_found(line, value):
    assert found(line) == [("SECRET", value)]


TELEGRAM = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"
assert len(TELEGRAM.split(":")[1]) == 35


@pytest.mark.parametrize(
    "line,value",
    [
        # words between the name and the separator
        ("Пароль от почты: Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль от Wi-Fi: Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль администратора: Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль 1: Xk9#mQ2v", "Xk9#mQ2v"),
        ("Токен доступа: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        (f"Токен бота: {TELEGRAM}", TELEGRAM),
        ("Секрет клиента = s3cr3tvalue", "s3cr3tvalue"),
        # markdown around the name
        ("**Пароль:** Xk9#mQ2v", "Xk9#mQ2v"),
        ("**Пароль**: Xk9#mQ2v", "Xk9#mQ2v"),
        ("__Пароль__: Xk9#mQ2v", "Xk9#mQ2v"),
        ("**Password:** hunter22x", "hunter22x"),
        # a login and a password in one value
        ("Логин/пароль: admin/Xk9#mQ2v", "admin/Xk9#mQ2v"),
        ("Логин / пароль: admin / Xk9#mQ2v", "admin / Xk9#mQ2v"),
        ("Логин/пароль: a/b", "a/b"),
        ("login / password: root / hunter22x", "root / hunter22x"),
        # a dash for a separator, when the value looks like a secret
        ("Пароль - Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль \N{EN DASH} Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль \N{EM DASH} Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль от почты - Xk9#mQ2v", "Xk9#mQ2v"),
        # a comma inside the value
        ("Пароль: pa$$,word1", "pa$$,word1"),
        ("Пароль: pa$$;word1", "pa$$;word1"),
        ("password=abcd,def9", "abcd,def9"),
        ("password=ab&cd9", "ab&cd9"),
        # English names with a space
        ("Secret key: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("API key: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("Access key = 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("private key: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
    ],
)
def test_more_secret_shapes_in_russian_and_english(line, value):
    assert found(line) == [("SECRET", value)]


@pytest.mark.parametrize(
    "text",
    [
        "Пароль - это секретная последовательность символов",
        "Пароль - залог безопасности",
        "Токен - это строка, которую выдаёт сервер",
        "Пароль - qwerty",  # a plain word after a dash is not told from prose
        "Секрет \N{EM DASH} ВАЖНО",
        "Пароль-это не слово",  # no spaces around the hyphen: a compound
        "Пароль для входа в систему: нужен",  # three words are too many between the name and the colon
    ],
)
def test_a_dash_before_a_plain_word_is_prose(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "line,value",
    [
        ("password=abcd,user=bob", "abcd"),
        ("password: abcd, user: bob", "abcd"),
        ("пароль=abc9d,host:db1", "abc9d"),
        ("Server=db;Password=abcd;Database=app", "abcd"),
        ("password=abcd&user=bob", "abcd"),
        ("password=abcd,", "abcd"),
    ],
)
def test_a_separator_that_starts_the_next_field_ends_the_value(line, value):
    assert found(line) == [("SECRET", value)]


def _prefixed_tokens():
    import random
    import string

    rng = random.Random(18)
    hexdigits = "0123456789abcdef"
    tokens = ["glpat-" + "".join(rng.choice(string.ascii_letters + string.digits + "_-") for _ in range(20))]
    tokens.append("dop_v1_" + "".join(rng.choice(hexdigits) for _ in range(64)))
    tokens += [prefix + "".join(rng.choice(hexdigits) for _ in range(32)) for prefix in ("shpat_", "shpca_", "shppa_", "shpss_")]
    return tokens


@pytest.mark.parametrize("token", _prefixed_tokens())
def test_gitlab_digitalocean_and_shopify_tokens_are_found(token):
    assert found(token, level=0) == [("SECRET", token)]
    assert found(f"deploy with {token} then rotate it", level=0) == [("SECRET", token)]


def test_a_hex_string_without_a_prefix_is_left_alone():
    assert kinds(_prefixed_tokens()[1].removeprefix("dop_v1_"), level=0) == []


def test_telegram_bot_token():
    assert found(f"use {TELEGRAM} now") == [("SECRET", TELEGRAM)]
    assert found(f"https://api.telegram.org/bot{TELEGRAM}/getMe") == [("SECRET", TELEGRAM)]


@pytest.mark.parametrize(
    "text",
    ["1234567:" + "A" * 35, "12345678901:" + "A" * 35, "123456789:" + "A" * 34, "123456789:" + "A" * 36, "ts 123456789:abc"],
)
def test_telegram_bot_token_needs_its_exact_shape(text):
    assert kinds(text) == []


# SECRET: long Russian names, and the cells of Markdown and TSV rows


@pytest.mark.parametrize(
    "line,value",
    [
        # three and four words between the name and the separator
        ("Секрет клиента для интеграции: s3cr3tvalue", "s3cr3tvalue"),
        ("Пароль для входа в систему: Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль от учётной записи администратора = Xk9#mQ2v", "Xk9#mQ2v"),
        ("Токен доступа к API бота: 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
        ("**Пароль для входа в систему:** Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль для входа в систему: 'мой длинный пароль'", "мой длинный пароль"),
        ("Пароль для входа в систему: Xk9#mQ2v и логин admin", "Xk9#mQ2v"),
        # a dash after them, when the value looks like a secret
        ("Пароль для входа в систему - Xk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль от учётной записи администратора \N{EM DASH} Xk9#mQ2v", "Xk9#mQ2v"),
    ],
)
def test_up_to_four_words_between_a_russian_name_and_its_separator(line, value):
    assert found(line) == [("SECRET", value)]


@pytest.mark.parametrize(
    "text",
    [
        "Пароль для входа в нашу корпоративную систему: Xk9#mQ2v",  # five words are one too many
        "Пароль для входа в нашу корпоративную систему - Xk9#mQ2v",
        # after a long name only a value that looks like a secret counts: a plain word is told from prose no better than before
        "Пароль для входа в систему: нужен",
        "Секрет успеха в бизнесе: упорство",
        "Токен доступа к API бота: действует",
        "Пароль для входа в систему: нажмите кнопку Войти",
        "Пароль для входа в систему - нужен",
        "Пароль для входа в систему: ******",
        "Пароль для входа в систему: [SECRET_1]",
        "Пароль для входа в систему: ${DB_PASSWORD}",
    ],
)
def test_a_long_russian_name_needs_a_secret_shaped_value(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "line,value",
    [
        ("| Пароль | Xk9#mQ2v |", "Xk9#mQ2v"),
        ("|Пароль|Xk9#mQ2v|", "Xk9#mQ2v"),
        ("| Пароль от почты | Xk9#mQ2v | почта |", "Xk9#mQ2v"),
        ("| Пароль для входа в систему | Xk9#mQ2v |", "Xk9#mQ2v"),
        ("| 1 | Почта | Пароль | Xk9#mQ2v |", "Xk9#mQ2v"),
        ("| **Пароль** | Xk9#mQ2v |", "Xk9#mQ2v"),
        ("| Пароль: | Xk9#mQ2v |", "Xk9#mQ2v"),  # a colon after the name is part of the label
        ("| **Пароль:** | Xk9#mQ2v |", "Xk9#mQ2v"),
        ("| **Пароль**: | Xk9#mQ2v |", "Xk9#mQ2v"),
        ("Пароль:\tXk9#mQ2v", "Xk9#mQ2v"),
        # where the value ends is what the plain rules say: a comma before a space, a quote, a field of its own
        ("Пароль\tXk9#mQ2v, логин: bob", "Xk9#mQ2v"),
        ("| Пароль | pa$$,word1 |", "pa$$,word1"),
        ('| Пароль | "Xk9#mQ2v" |', "Xk9#mQ2v"),
        ("Пароль\tXk9#mQ2v,user=bob", "Xk9#mQ2v"),
        ("| Токен бота | 123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ | активен |", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"),
        ("| Пароль | Xk9#mQ2v (почта) |", "Xk9#mQ2v"),
        ("| Пароль | `Xk9#mQ2v` |", "`Xk9#mQ2v`"),  # the marks around a value belong to it
        ("Пароль | Xk9#mQ2v", "Xk9#mQ2v"),  # a row without outer pipes
        ("| API-ключ | 9f8e7d6c5b4a3b2c |", "9f8e7d6c5b4a3b2c"),
        ("| Секретный ключ | pa$$word1 |", "pa$$word1"),
        ("| Пароль | Привет2026 |", "Привет2026"),
        ("Пароль\tXk9#mQ2v", "Xk9#mQ2v"),
        ("Сервис\tПароль\tXk9#mQ2v\tпочта", "Xk9#mQ2v"),
        ("Пароль от почты\tXk9#mQ2v", "Xk9#mQ2v"),
        ("Пароль \t Xk9#mQ2v", "Xk9#mQ2v"),
        ("Сервис\tПочта\nПароль\tXk9#mQ2v\nЛогин\tadmin", "Xk9#mQ2v"),  # a row of its own
    ],
)
def test_a_secret_in_the_cell_after_its_name(line, value):
    assert found(line) == [("SECRET", value)]


@pytest.mark.parametrize(
    "text",
    [
        "| Пароль | строка |",
        "| Пароль | Введите пароль |",
        "| Пароль | **обязательно** |",
        "| Пароль | нет |",
        "| Пароль | скрыт |",
        "| Пароль | ****** |",
        "| Пароль | [SECRET_1] |",
        "| Пароль | ${PASSWORD} |",
        "| Пароль | см. ниже |",
        "| Пароль | строка(64) |",  # a table of fields holds types, words and names where a table of logins holds secrets
        "| Токен | Optional[str] |",
        "| Токен | JWT-токен |",
        "| Секрет | API_KEY |",
        "| Токен | DEEPSEEK_API_KEY | OPENROUTER_API_KEY |",
        "секрет|api[ _\\-]?ключ|(?:секретный|приватный) ключ",  # an alternation in a pattern
        "| Token | string |",
        "| token | string(64) |",  # English names are read only before a colon or an equals sign: such a table would be all false alarms
        "| password | Optional[str] |",
        "| Логин: | Пароль: |",
        "| Пароль: | Логин: |",  # a label with a colon is a word
        "| Пароль | Статус: ок |",
        "| Сервис | Логин | Пароль |",  # the name is the last cell: no value
        "| Пароль |",
        "| Пароль | Логин |",
        "Пароль\tстрока",
        "\tPassword\tstring",  # a Go struct field
        "echo $PASSWORD | base64",  # a shell pipe
        "cat password | xargs -n1",
        "password|passwd|pwd",  # an alternation
        "if (a || password || b)",
        "| Keyboard | Xk9#mQ2v |",
        "| Пароли | Xk9#mQ2v |",  # a longer word that starts like a name
        "| суперпароль | Xk9#mQ2v |",
    ],
)
def test_a_cell_after_a_name_that_is_no_secret_is_left_alone(text):
    assert kinds(text) == []


# SECRET: a value that is wholly another kind keeps that kind in the rules for long names, dashes after them and cells

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"


@pytest.mark.parametrize(
    "text,kind,value",
    [
        # three and four words before a colon, an equals sign or a dash
        ("Пароль выслан на почту: ivan@acme.com", "EMAIL", "ivan@acme.com"),
        ("Пароль придёт вам на почту = ivan@acme.com", "EMAIL", "ivan@acme.com"),
        ("Пароль отправлен на адрес: ivan@acme.com", "EMAIL", "ivan@acme.com"),
        ("Пароль выслан на нашу почту - ivan@acme.com", "EMAIL", "ivan@acme.com"),
        ("Пароль выслан на нашу почту \N{EM DASH} ivan@acme.com", "EMAIL", "ivan@acme.com"),
        ("Пароль выслан на почту: 'ivan@acme.com'", "EMAIL", "ivan@acme.com"),
        ("Пароль выслан на номер: +79991234567", "PHONE", "+79991234567"),
        ("Пароль выслан на этот номер - +7 (912) 345-67-89", "PHONE", "+7 (912) 345-67-89"),
        ("Токен доступа к серверу: 203.0.113.7", "IP", "203.0.113.7"),
        ("Токен доступа к серверу - 2001:db8::8a2e:370:7334", "IP", "2001:db8::8a2e:370:7334"),
        ("Секрет клиента для интеграции: DE89370400440532013000", "IBAN", "DE89370400440532013000"),
        ("Пароль для оплаты картой клиента: 4111111111111111", "CARD", "4111111111111111"),
        ("Токен доступа к API бота: " + JWT, "JWT", JWT),
        # cells
        ("| Пароль | ivan@acme.com |", "EMAIL", "ivan@acme.com"),
        ("| Токен | 10.0.0.5 |", "IP", "10.0.0.5"),
        ("| Токен | +79991234567 |", "PHONE", "+79991234567"),
        ("| Токен | `ivan@acme.com` |", "EMAIL", "ivan@acme.com"),
        ("Токен\t+79991234567", "PHONE", "+79991234567"),
        ("Пароль\tivan@acme.com\tпочта", "EMAIL", "ivan@acme.com"),
        ("| Токен | " + JWT + " |", "JWT", JWT),
    ],
)
def test_a_value_that_is_wholly_another_kind_keeps_it(text, kind, value):
    assert found(text) == [(kind, value)]


@pytest.mark.parametrize(
    "text,kind,value",
    [
        # the pipe that ends a compact row sticks to the last word of the line, and is not part of the address
        ("|Пароль выслан на нашу почту - ivan@acme.com|", "EMAIL", "ivan@acme.com"),
        ("|Токен доступа к серверу: 203.0.113.7|", "IP", "203.0.113.7"),
    ],
)
def test_a_pipe_that_ends_a_row_does_not_hide_the_kind_of_a_value(text, kind, value):
    assert found(text) == [(kind, value)]


@pytest.mark.parametrize("text", ["|Токен доступа к серверу: 3600|", "|Токен доступа к API бота - 2026-12-31|"])
def test_a_pipe_that_ends_a_row_does_not_hide_a_quantity(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "text,value",
    [
        ("Пароль выслан на почту: ivan@acme.com.zz9", "ivan@acme.com.zz9"),  # no address, no phone: the value is still a secret
        ("Пароль выслан на почту: Xk9#ivan@acme", "Xk9#ivan@acme"),
        ("Пароль выслан на номер: 7x999123456", "7x999123456"),
        ("| Токен | 10.0.0.5x9# |", "10.0.0.5x9#"),
    ],
)
def test_a_value_that_only_looks_like_another_kind_is_still_a_secret(text, value):
    assert ("SECRET", value) in found(text)


@pytest.mark.parametrize("text", ["Пароль: ivan@acme.com", "Пароль - ivan@acme.com", "Токен доступа: +79991234567"])
def test_the_forms_of_up_to_two_words_name_such_a_value_a_secret_as_before(text):
    assert [kind for kind, _ in found(text)] == ["SECRET"]


# SECRET: a whole value that is a number, a date, a time, a duration, an address on the net, a path or a handle is said of the
# secret, not the secret, in the rules for long names, dashes after them and cells

FACTS = [
    # after three or four words
    "Пароль для входа в систему: 8-20 символов, буквы и цифры",
    "Токен доступа действителен до - 2026-12-31",
    "Токен доступа действует до: 31.12.2026",
    "Токен доступа живёт 24 часа - 86400 секунд",
    "Токен доступа к сервису истекает - 2026-11-01",
    "Секрет успеха в бизнесе: 10000 часов практики",
    "Секрет успеха в бизнесе - 10000 часов практики",
    "Секрет компании на 2026 год: +15%",
    "Пароль в этой системе - 100% безопасен",
    "Пароль в личном кабинете меняется раз в 90 дней: 2-3 раза в год",
    "Токен доступа к API действует - 15мин",
    "Токен доступа к API живёт - 24ч",
    "Токен доступа к API живёт - 10:30",
    "Секрет полишинеля в нашей компании - Q3-2026",
    "Ключ доступа к API выдаётся на 30 дней: 2026-11-30",
    "Токен доступа действителен до: 2026-12-31T10:00:00Z",
    "Версия клиента для этого токена доступа: v2.1.0",
    "API ключ получите в кабинете: https://example.com/settings",
    "Ключ API выдаётся в личном кабинете: https://example.com/settings/api",
    "Ключ API выдаётся в личном кабинете: www.example.com/settings",
    "Закрытый ключ храните в надёжном месте: ~/.ssh/id_rsa",
    "Секретный ключ хранится в файле: /etc/app/secret.key",
    "Секретный ключ хранится в этом файле: ./config/secret.key",
    "Секретный ключ хранится в файле на диске: C:\\Users\\app\\secret.key",
    "Секретный ключ лежит в хранилище секретов: vault:kv/app",
    "Пароль администратора базы данных хранится в Vault: kv/db/admin",
    "Ключ доступа к серверу выдаёт администратор: @admin_support",
    "Токен бота можно получить у: @BotFather",
    "Токен бота можно получить в чате - @BotFather",
    "Секрет клиента для интеграции - OAuth2",
    "Пароль для администратора сервера - SHA-256 хэш",
    "Токен доступа к API подписан: HS256",
    # cells
    "| Пароль | 8-20 |",
    "| Пароль | 8-20 символов |",
    "| Токен | 3600 |",
    "| Токен | 2026-12-31 |",
    "| Токен | 31.12.2026 |",
    "| Токен | 24ч |",
    "| Токен | ~15 мин |",
    "| Токен | 1 час |",
    "| Токен | 90d |",
    "| Токен | 10:30 |",
    "| Секрет | v2.1.0 |",
    "| Секрет | Q3-2026 |",
    "| Секрет | 2026 |",
    "| Секрет | 24/7 |",
    "| Секрет | https://example.com |",
    "| Секрет | ~/.ssh/id_rsa |",
    "| Секрет | /etc/app/secret.key |",
    "| Секрет | kv/db/admin |",
    "| Токен | @BotFather |",
    "| Секрет | OAuth2 |",
    "| Пароль | SHA-256 |",
    "| Токен | HS256 |",
    "| Токен | AES-256 |",
    "Пароль\tSHA-256",
    "Пароль\t8-20",
    "Токен\t3600",
    "Секрет\t2026-12-31",
    "Токен\t~/.ssh/token",
]


@pytest.mark.parametrize("text", FACTS)
def test_a_number_date_duration_url_path_or_handle_is_no_secret(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "text,value",
    [
        # eight digits and more are a password or a PIN, shorter ones a quantity
        ("слушай, пароль от вайфая в офисе - 12345678", "12345678"),
        ("| Пароль | 12345678 |", "12345678"),
        ("Пароль для входа в систему: 4815162342", "4815162342"),
        ("| Токен | 1234-5678 |", "1234-5678"),
        # a base64 value that starts with a slash is no path, a handle with a digit is no handle, digits and letters are no unit
        ("| Пароль | /Xk9+mQ2vLpz7= |", "/Xk9+mQ2vLpz7="),
        ("| Пароль | @dmin2026 |", "@dmin2026"),
        ("Пароль для входа в систему: 2026Xk9#", "2026Xk9#"),
        ("| Пароль | 123abc45 |", "123abc45"),
        ("| Пароль | 90days! |", "90days!"),
        ("| Пароль | HS256x9# |", "HS256x9#"),
        ("| Пароль | Sha256Xk9 |", "Sha256Xk9"),
        ("| Пароль | Xk9/mQ2v/Lpz |", "Xk9/mQ2v/Lpz"),
        ("Токен доступа к API бота - 9f8e7d6c5b4a3b2c", "9f8e7d6c5b4a3b2c"),
    ],
)
def test_what_looks_like_a_quantity_but_is_a_secret_is_still_found(text, value):
    assert ("SECRET", value) in found(text)


# SECRET: passphrases and passwords with brackets are secrets in a cell, a type or a field name is not

PASSPHRASES = [
    "correct-horse-battery-staple",
    "blue_sky_morning",
    "my_secret_password",
    "тест-пароль-долгий",
    "sk_live_abc",
    "Summer-Winter",  # two words are a passphrase too, unless one of them is a word of credentials: access_token, client_secret
    "admin-admin",
    "P@ss(w0rd)1",
    "ab[cd]ef12",
    "Xk9<mQ2v",
    "Xk9[mQ2vLpz7",
    "(Xk9#mQ2v)",
    "Qwerty{2026}",
    "x9)Kd[2m#Lp",
]


@pytest.mark.parametrize("value", PASSPHRASES)
def test_a_passphrase_or_a_password_with_brackets_is_a_secret_in_a_cell(value):
    assert ("SECRET", value) in found(f"| Пароль | {value} |")
    assert ("SECRET", value) in found(f"Пароль\t{value}")


@pytest.mark.parametrize("value", PASSPHRASES)
def test_a_passphrase_or_a_password_with_brackets_is_a_secret_after_a_long_name(value):
    assert ("SECRET", value) in found(f"Пароль для входа в систему: {value}")
    assert ("SECRET", value) in found(f"Пароль для входа в систему - {value}")


def test_random_passwords_with_brackets_are_found_in_a_cell():
    import random
    import string

    rng = random.Random(5)
    alphabet = string.ascii_letters + string.digits + "!@#^&*()-_=+[].>/?"  # no quote, comma or semicolon, no $ % { < to start
    misses = []
    for _ in range(300):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(12, 16)))
        # found as a secret, or as what it happens to look like (one of them reads like an address, "Tn7Pm@Pe5h.DK")
        if not any(value.startswith(text[:3]) for _, text in found(f"| Пароль | {value} |")):
            misses.append(value)
    assert misses == []


@pytest.mark.parametrize(
    "text",
    [
        "| Токен | bcrypt(12) |",
        "| Токен | List<String> |",
        "| Токен | int[] |",
        "| Токен | Dict[str,int] |",
        "| Токен | access_token |",
        "| Токен | refresh-token |",
        "| Токен | Bearer-токен |",
        "| Секрет | client_secret |",
        "| Токен | AUTH_TOKEN_NAME |",
        "Токен доступа к API - Bearer-токен",
        "Токен доступа к API бота: access_token",
        "Токен доступа к API бота: Optional[str]",
        "Токен доступа к API бота - строка(64)",
    ],
)
def test_a_type_or_a_field_name_is_no_secret_in_the_rules_for_long_names_and_cells(text):
    assert kinds(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "секрет|api[ _\\-]?ключ|(?:секретный|приватный) ключ",  # the pipes of an alternation make no table
        "токен|секрет|api[x|(?:y)|z9#",
        "if (x) { return секрет|Xk9#mQ2v; }",
    ],
)
def test_pipes_without_a_table_around_them_make_no_cells(text):
    assert kinds(text) == []


# SECRET: a header cell with the name of a secret marks its column, and what stands under it in the same table is secret

GHP = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"


def secrets(text):
    return [value for kind, value in found(text) if kind == "SECRET"]


@pytest.mark.parametrize(
    "text,values",
    [
        ("| Логин | Пароль |\n|---|---|\n| admin | Xk9#mQ2v |", ["Xk9#mQ2v"]),
        ("| Логин | Пароль |\n|---|---|\n| admin | Xk9#mQ2v |\n| bob | Yk8#nR3w |\n", ["Xk9#mQ2v", "Yk8#nR3w"]),
        ("| Логин | Пароль |\n|:---|---:|\n| admin | Xk9#mQ2v |", ["Xk9#mQ2v"]),
        ("| Логин | Пароль |\n| :---: | :---: |\n| admin | Xk9#mQ2v |", ["Xk9#mQ2v"]),
        ("Логин | Пароль\n--- | ---\nadmin | Xk9#mQ2v", ["Xk9#mQ2v"]),  # no outer pipes
        ("| Логин | Пароль |\r\n|---|---|\r\n| admin | Xk9#mQ2v |\r\n", ["Xk9#mQ2v"]),
        ("| Пароль |\n|---|\n| Xk9#mQ2v |", ["Xk9#mQ2v"]),  # a table of one column
        ("| **Логин** | **Пароль** |\n|---|---|\n| admin | `Xk9#mQ2v` |", ["`Xk9#mQ2v`"]),
        ("| Пароль от почты | Логин |\n|---|---|\n| Xk9#mQ2v | admin |", ["Xk9#mQ2v"]),  # the name leads the table
        ("| Сервис | Логин | Пароль | Токен |\n|---|---|---|---|\n| CRM | admin | Xk9#mQ2v | " + GHP + " |", ["Xk9#mQ2v", GHP]),
        # English names of a header
        ("| User | Password |\n|---|---|\n| admin | hunter22x |", ["hunter22x"]),
        ("| User | API key |\n|---|---|\n| admin | 9f8e7d6c5b4a3b2c |", ["9f8e7d6c5b4a3b2c"]),
        ("| User | Admin password |\n|---|---|\n| admin | hunter22x |", ["hunter22x"]),
        ("| User | DB_PASSWORD |\n|---|---|\n| admin | Xk9#mQ2v |", ["Xk9#mQ2v"]),
        # TSV
        ("Логин\tПароль\nadmin\tXk9#mQ2v\nbob\tYk8#nR3w", ["Xk9#mQ2v", "Yk8#nR3w"]),
        ("Сервис\tЛогин\tПароль\nCRM\tadmin\tXk9#mQ2v", ["Xk9#mQ2v"]),
        ("Логин\tПароль\r\nadmin\tXk9#mQ2v\r\n", ["Xk9#mQ2v"]),
        ("Login\tPassword\nadmin\thunter22x", ["hunter22x"]),
    ],
)
def test_the_column_under_a_header_with_the_name_of_a_secret_is_secret(text, values):
    assert secrets(text) == values


@pytest.mark.parametrize(
    "text,values",
    [
        # a blank line ends the table, and so does a line without a pipe or a tab
        ("| Логин | Пароль |\n|---|---|\n| a | Xk9#mQ2v |\n\n| b | Yk8#nR3w |", ["Xk9#mQ2v"]),
        ("| Логин | Пароль |\n|---|---|\n| a | Xk9#mQ2v |\nЕщё текст\n| b | Yk8#nR3w |", ["Xk9#mQ2v"]),
        ("Логин\tПароль\nadmin\tXk9#mQ2v\n\nbob\tYk8#nR3w", ["Xk9#mQ2v"]),
        ("Логин\tПароль\nadmin\tXk9#mQ2v\nПримечание: пароль меняется раз в год\nbob\tYk8#nR3w", ["Xk9#mQ2v"]),
        # a later table has a header of its own
        ("| Логин | Пароль |\n|---|---|\n| a | Xk9#mQ2v |\n\n| Хост | Порт |\n|---|---|\n| db | Yk8#nR3w |", ["Xk9#mQ2v"]),
        ("| Логин | Пароль |\n|---|---|\n| a | Xk9#mQ2v |\n| Хост | Токен |\n|---|---|\n| db | Yk8#nR3w9 |", ["Xk9#mQ2v", "Yk8#nR3w9"]),
    ],
)
def test_the_column_of_a_header_goes_on_to_the_end_of_its_table(text, values):
    assert secrets(text) == values


@pytest.mark.parametrize(
    "text",
    [
        "| Логин | Пароль |\n|---|---|\n| admin | нет |\n| bob | скрыт |",  # words and placeholders
        "| Логин | Пароль |\n|---|---|\n| admin | ****** |\n| bob | [SECRET_1] |",
        "| Логин | Пароль |\n|---|---|\n| Xk9#mQ2v | admin |",  # a secret in another column
        "| Токен | TTL |\n|---|---|\n| 3600 | 15 мин |\n| 7200 | 2026-12-31 |",  # quantities
        "| Параметр | Токен |\n|---|---|\n| тип | string(64) |\n| поле | access_token |\n| срок | 3600 |",
        "| Политика паролей | Срок |\n|---|---|\n| Xk9#mQ2v | 90 |",  # the header is no name
        "| Параметр | Password |\n|---|---|\n| тип | Optional[str] |",
        "Логин\tПароль\nadmin\tнет",
        "Политика паролей\tСрок\nXk9#mQ2v\t90",
        "| Логин | Пароль |\n| admin | нет |",  # no row of dashes: no Markdown table
    ],
)
def test_a_column_under_a_header_holds_no_secret_in_these(text):
    assert kinds(text) == []


def test_a_column_under_a_header_keeps_the_kind_of_an_address():
    assert found("| Логин | Пароль |\n|---|---|\n| admin | ivan@acme.com |") == [("EMAIL", "ivan@acme.com")]


@pytest.mark.parametrize(
    "text,values",
    [
        # rows of a list, not a header over columns: a name with a value in its row is no header, so the first cells under it
        # (E-mail, Wi-Fi) are labels and not secrets
        ("Пароль\tXk9#mQ2v\nE-mail\tbob@x.io\nWi-Fi\tguest", ["Xk9#mQ2v"]),
        ("Пароль\thunter22x\nWi-Fi\tguest\nSSH-ключ\tid_rsa", ["hunter22x"]),
        ("Токен\t9f8e7d6c5b4a3b2c\nE-mail\tbob@x.io", ["9f8e7d6c5b4a3b2c"]),
        ("| Токен | 9f8e7d6c5b4a3b2c |\n|---|---|\n| E-mail | bob@x.io |", ["9f8e7d6c5b4a3b2c"]),
        # a header of labels, even with punctuation in them, is one
        ("Логин\tПароль (временный)\nadmin\tXk9#mQ2v", ["Xk9#mQ2v"]),
        ("№\tЛогин\tПароль\n1\tadmin\tXk9#mQ2v", ["Xk9#mQ2v"]),
    ],
)
def test_a_row_of_a_list_is_not_taken_for_the_header_of_a_table(text, values):
    assert secrets(text) == values
