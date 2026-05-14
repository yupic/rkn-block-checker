# Hard-coded sample lists. The official RKN registry has ~1M entries which
# is way too noisy for a "is this connection blocked?" check — 20 well-known
# sites per category give a good enough verdict.

WHITE_URLS: dict[str, str] = {
    "gosuslugi":   "https://www.gosuslugi.ru/",
#    "gov.ru":      "https://www.gov.ru/",
    "mos.ru":      "https://www.mos.ru/",
#    "rkn":         "https://rkn.gov.ru/",
    "nalog":       "https://www.nalog.gov.ru/",
    "yandex":      "https://ya.ru/",
    "yandex-maps": "https://yandex.ru/maps/",
    "kinopoisk":   "https://www.kinopoisk.ru/",
    "sberbank":    "https://www.sberbank.ru/",
#    "vtb":         "https://www.vtb.ru/",
    "alfabank":    "https://alfabank.ru/",
    "vk":          "https://vk.com/",
    "ok":          "https://ok.ru/",
    "ozon":        "https://www.ozon.ru/",
    "wildberries": "https://www.wildberries.ru/",
    "avito":       "https://www.avito.ru/",
    "lenta":       "https://lenta.ru/",
    "rbc":         "https://www.rbc.ru/",
    "tass":        "https://tass.ru/",
    "rutube":      "https://rutube.ru/",
    "dzen":        "https://dzen.ru/",
}


BLACK_URLS: dict[str, str] = {
#    "facebook":     "https://www.facebook.com/",
#    "linkedin":     "https://www.linkedin.com/",
#    "discord":      "https://discord.com/",
#    "dailymotion":  "https://www.dailymotion.com/",
#    "soap2day":     "https://soap2day.day/",
#    "rutracker":    "https://rutracker.org/",
#    "tor-project":  "https://www.torproject.org/",
#    "protonvpn":    "https://protonvpn.com/",
#    "patreon":      "https://www.patreon.com/",
#    "bbc-russian":  "https://www.bbc.com/russian",
#    "dw-russian":   "https://www.dw.com/ru/",
    "amazon":       "https://www.amazon.com/",
    "akamai":       "https://www.akamai.com/",
    "aws":          "https://aws.amazon.com/",
    "cloudflare":   "https://www.cloudflare.com/",
    "hetzner":      "https://www.hetzner.com/",
    "ovh":          "https://www.ovhcloud.com/",
    "deepl":        "https://www.deepl.com/",
    "instagram":    "https://www.instagram.com/",
    "twitter/x":    "https://x.com/",
    "telegram":     "https://web.telegram.org/",
    "google":       "https://google.com/",
    "youtube":      "https://youtube.com/",
    "chatgpt":      "https://chatgpt.com",
    "meduza":       "https://meduza.io/",
    "fontanka":     "https://www.fontanka.ru",
}


# Substrings that show up on ISP "this site is blocked" stub pages.
# Matched against body[:2000].lower() in http.py.
STUB_MARKERS: tuple[str, ...] = (
    "доступ ограничен",
    "доступ к запрашиваемому ресурсу",
    "решению роскомнадзора",
    "решением суда",
    "заблокирован",
    "blocked by roskomnadzor",
    "blocked by rkn",
    "rkn.gov.ru/org/register",
    "единый реестр",
    "запрещен",
)
