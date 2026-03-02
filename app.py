from __future__ import annotations

import io
import json
import os
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv
from PIL import Image
import re

import google.generativeai as genai
from duckduckgo_search import DDGS
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# =========================
# 1) 政府/外部黑名單來源（請在這裡填入）
# =========================
#
# 你未來只要把這個變數改成「165 反詐騙假網站」公開資料的 JSON/CSV 連結即可。
# 例如：資料開放平台的 API 端點、或直接可下載的 CSV 檔。
# 目前先放一個標準 CSV 連結佔位符，之後你可以自行改成 data.gov.tw 上 165 黑名單的真實 CSV 下載網址。
BLACKLIST_SOURCE_URL = "165_blacklist.csv"

# 常見可疑關鍵字（特徵防護）。你之後也可以自己再加。
SUSPICIOUS_KEYWORDS: list[str] = [
    # 原本的
    ".xyz",
    "free-money",
    "free-money.",
    "free-money/",
    "freegift",
    "freecash",
    # 常見詐騙頂級網域 / 網址型態（至少 10 個以上新增）
    ".top",
    ".vip",
    ".icu",
    ".click",
    ".live",
    ".shop",
    ".work",
    ".monster",
    ".cc",
    ".pw",
    # 常見誘導/釣魚字串
    "login-update",
    "secure-verify",
    "account-verify",
    "verify-now",
    "update-billing",
    "password-reset",
    "support-center",
    "wallet-connect",
    "claim-reward",
    "limited-time",
    "urgent",
    "bonus",
    "giveaway",
    "airdrop",
    # 常見拼字偽裝
    "faceb00k",
    "g00gle",
    "paypaI",  # 注意：最後一個字是大寫 i（I），常見混淆
    # 其他常見可疑技巧
    "xn--",  # punycode
    "@",  # user:pass@host 的混淆手法常見於釣魚連結
]

POSSIBLE_URL_FIELDS = [
    "url",
    "URL",
    "網址",
    "网站",
    "網站",
    "site",
    "website",
    "domain",
    "link",
    "來源",
]

GEMINI_API_ENV_VAR = "GEMINI_API_KEY"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

GEMINI_SYSTEM_PROMPT = (
    "你是一位台灣警政署 165 級別的防詐騙專家。請仔細掃描這張圖片，判斷是否包含詐騙特徵、健康謠言、"
    "帶風向/情緒煽動的內容，或只是一般安全的日常資訊。\n\n"
    "請嚴格依照以下標籤分類（只能四選一）：\n"
    "『🔴 詐騙高風險』：內容涉及要求匯款、點擊不明網址、索取驗證碼/個資、宣稱中獎或穩賺不賠的投資。\n"
    "『🟡 健康謠言/假新聞』：與健康或公共政策相關，但內容誇大恐嚇、未經證實、或偽造政府/權威單位說法。\n"
    "『🔵 帶風向/情緒煽動疑慮』：內容未必直接詐騙或健康謠言，但充滿強烈情緒字眼、試圖挑起社會對立、"
    "使用誇大聳動標題、或具有明顯網軍操作特徵。\n"
    "『🟢 安全與日常資訊』：一般的早安圖文字、真實新聞截圖、或無害的親友問候。\n\n"
    "輸出格式必須是乾淨 JSON，只能包含：\n"
    '- \"category\"：上述四種標籤之一（完全一致）。\n'
    '- \"analysis\"：用對待長輩般親切、好懂的白話文（約 100-150 字），說明為什麼這樣分類並給出建議。\n\n'
    "請不要輸出任何額外說明或 Markdown，只輸出 JSON。"
)

GEMINI_URL_SYSTEM_PROMPT = (
    "你是一位台灣警政署 165 級別的防詐騙專家。你會收到系統整理好的網址檢查情報，"
    "其中包含是否命中 165 詐騙黑名單、命中的可疑關鍵字、網域與其他技術細節。"
    "請先充分理解這些背景情報，再用溫暖、專業、具同理心且條理分明的繁體中文，"
    "寫給一般民眾看的防詐騙分析報告；若風險較高要明確提醒與給建議，若目前看起來安全也要提醒保持警覺。"
)

GEMINI_SMS_SYSTEM_PROMPT = (
    "你是一位『溫暖的銀髮族資訊守門員』，專門協助長者判斷收到的簡訊或 LINE 訊息是否安全。"
    "你會收到：1) 使用者貼上的訊息原文 2) 系統針對訊息內網址做的比對結果（是否命中 165 黑名單、可疑關鍵字）。\n\n"
    "請嚴格遵循以下分類規則（只能四選一）：\n"
    "『🔴 詐騙高風險』：只要內容涉及要求匯款、點擊不明網址、索取驗證碼/個資、宣稱中獎或穩賺不賠的投資。\n"
    "『🟡 健康謠言/假新聞』：內容沒有直接騙錢，但包含誇大的健康恐嚇、未經證實的偏方、或偽造的政府/社會政策。\n"
    "『🔵 帶風向/情緒煽動疑慮』：內容可能未達直接詐騙或具體健康謠言標準，但充滿強烈情緒字眼、試圖挑起社會對立、"
    "使用誇大聳動標題、或具有明顯網軍操作特徵的訊息。\n"
    "『🟢 安全與日常資訊』：一般的早安圖文字、真實的新聞、或是無害的親友問候。\n\n"
    "輸出格式必須是『乾淨 JSON』，只能包含兩個欄位：\n"
    '- \"category\"：只能是上述三種標籤其中一個（完全一致）。\n'
    '- \"analysis\"：用對待長輩般親切、好懂的白話文，解釋為什麼這樣分類並給建議，約 100-150 字。\n\n'
    "非常重要：只輸出 JSON，不要加任何多餘文字、不要 Markdown、不要程式碼區塊。"
)

GEMINI_AUDIO_SYSTEM_PROMPT = (
    "你是一位親切的銀髮族防詐騙與闢謠志工。請直接聆聽這段音訊，判斷內容是否有詐騙疑慮、"
    "是否屬於健康謠言/假新聞，或只是單純的問候與日常資訊。\n\n"
    "請嚴格依照以下標籤分類（只能四選一）：\n"
    "『🔴 詐騙高風險』：內容涉及要求匯款、點擊不明網址、索取驗證碼/個資、宣稱中獎或穩賺不賠的投資。\n"
    "『🟡 健康謠言/假新聞』：內容沒有直接騙錢，但包含誇大的健康恐嚇、未經證實的偏方、或偽造的政府/社會政策。\n"
    "『🔵 帶風向/情緒煽動疑慮』：內容可能未達直接詐騙或具體健康謠言標準，但充滿強烈情緒字眼、試圖挑起社會對立、"
    "使用誇大聳動標題、或具有明顯網軍操作特徵的訊息。\n"
    "『🟢 安全與日常資訊』：一般的早安問候、真實新聞朗讀、或無害的親友關心。\n\n"
    "輸出格式必須是乾淨 JSON，只能包含：\n"
    '- \"category\"：上述三種標籤之一（完全一致）。\n'
    '- \"analysis\"：用對待長輩般親切、好懂的白話文（約 100-150 字），說明為什麼這樣分類並給出建議。\n\n'
    "請不要輸出任何額外說明或 Markdown，只輸出 JSON。"
)


def _normalize_domain(raw_url: str) -> str:
    s = (raw_url or "").strip()
    if not s:
        return ""
    parsed = urlparse(s if "://" in s else f"https://{s}")
    host = (parsed.netloc or "").lower().strip()
    if "@" in host:
        host = host.split("@")[-1]
    if ":" in host:
        host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def _normalize_url(raw_url: str) -> str:
    s = (raw_url or "").strip()
    if not s:
        return ""
    parsed = urlparse(s if "://" in s else f"https://{s}")
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower().strip()
    if "@" in netloc:
        netloc = netloc.split("@")[-1]
    if netloc.startswith("www."):
        netloc = netloc[4:]
    path = parsed.path or ""
    return f"{scheme}://{netloc}{path}".rstrip("/")


def _extract_urls_from_json(data: object) -> list[str]:
    results: list[str] = []

    def walk(x: object) -> None:
        if isinstance(x, str):
            if "://" in x or "." in x:
                results.append(x)
            return
        if isinstance(x, list):
            for item in x:
                walk(item)
            return
        if isinstance(x, dict):
            for k, v in x.items():
                if k in POSSIBLE_URL_FIELDS and isinstance(v, str):
                    results.append(v)
                else:
                    walk(v)

    walk(data)
    return results


def _extract_urls_from_csv_df(df: pd.DataFrame) -> list[str]:
    lower_to_col = {str(c).strip().lower(): c for c in df.columns}

    for key in POSSIBLE_URL_FIELDS:
        c = lower_to_col.get(key.lower())
        if c is not None:
            series = df[c].dropna().astype(str)
            return series.tolist()

    all_vals = df.astype(str).replace("nan", "").values.ravel().tolist()
    return [v for v in all_vals if v and ("://" in v or "." in v)]


def _extract_urls_from_csv_text(csv_text: str) -> list[str]:
    df = pd.read_csv(io.StringIO(csv_text))
    return _extract_urls_from_csv_df(df)


def extract_urls_from_text(text: str) -> list[str]:
    """從簡訊文字中以正規表達式萃取網址（含 http/https 及部分裸網域）。"""
    if not text:
        return []

    urls: set[str] = set()

    # 1) 先抓 http/https 開頭的完整網址
    pattern_http = re.compile(r"https?://[^\s<>\"']+")
    for match in pattern_http.findall(text):
        urls.add(match.strip().strip("。，、,.!?；;"))

    # 2) 再抓像 example.com/path 這種無協定的網址
    pattern_domain = re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|tw|top|vip|icu|click|shop|live|cc|pw)(?:/[^\s<>\"']*)?"
    )
    for match in pattern_domain.findall(text):
        # 避免重複已抓過的 http/https
        if not match.startswith("http://") and not match.startswith("https://"):
            urls.add(match.strip().strip("。，、,.!?；;"))

    return sorted(urls)


@st.cache_data(ttl=600, show_spinner=False)
def live_fact_check(query: str) -> str:
    """使用 DuckDuckGo 對台灣官方查核站做即時查詢，回傳精簡文字摘要。"""
    q = (query or "").strip()
    if not q:
        return "（未提供足夠關鍵字，略過即時查核。）"

    search_query = (
        f"{q} site:mohw.gov.tw OR site:165.npa.gov.tw OR site:tfc-taiwan.org.tw"
    )

    try:
        with DDGS(timeout=10) as ddgs:
            results = list(ddgs.text(search_query, max_results=3))
    except Exception as e:
        return f"（即時查核失敗：{e}）"

    if not results:
        return "（在衛福部、165 防詐網或台灣事實查核中心暫時找不到明確相關的查核資料。）"

    lines: list[str] = []
    for idx, r in enumerate(results, start=1):
        title = r.get("title") or ""
        snippet = r.get("body") or r.get("description") or ""
        url = r.get("href") or r.get("url") or ""
        lines.append(
            f"{idx}. {title}\n   摘要：{snippet}\n   來源：{url}"
        )

    return "\n".join(lines)


@st.cache_data(ttl=3600, show_spinner=False)
def load_external_blacklist(source_url: str) -> tuple[set[str], str]:
    src = (source_url or "").strip()
    if not src:
        return set(), "尚未設定黑名單來源網址（目前只用關鍵字特徵比對）。"

    candidates: list[str] = []
    # 遠端 URL（http/https）：用 requests 抓取
    if src.startswith("http://") or src.startswith("https://"):
        try:
            # 忽略 SSL 憑證驗證，以避免部分政府站台憑證設定問題導致錯誤
            resp = requests.get(src, timeout=15, verify=False)
            resp.raise_for_status()
        except Exception as e:
            return set(), f"黑名單下載失敗：{e}"

        content_type = (resp.headers.get("content-type") or "").lower()
        text = resp.text

        if "application/json" in content_type or src.lower().endswith(".json"):
            try:
                candidates = _extract_urls_from_json(resp.json())
            except Exception as e:
                return set(), f"黑名單 JSON 解析失敗：{e}"
        else:
            try:
                candidates = _extract_urls_from_csv_text(text)
            except Exception:
                try:
                    candidates = _extract_urls_from_json(resp.json())
                except Exception as e:
                    return set(), f"黑名單解析失敗（非 JSON/CSV 或格式不符）：{e}"
    # 其他情況：視為本機檔案路徑，用 pandas 直接讀取 CSV
    else:
        try:
            df = pd.read_csv(src)
        except Exception as e:
            return set(), f"本機黑名單 CSV 載入失敗：{e}"
        candidates = _extract_urls_from_csv_df(df)

    normalized: set[str] = set()
    for item in candidates:
        u = _normalize_url(item)
        d = _normalize_domain(item)
        if u:
            normalized.add(u)
        if d:
            normalized.add(d)

    return normalized, f"黑名單載入成功：共 {len(normalized)} 筆（已做基本正規化）。"


def keyword_hits(raw_url: str) -> list[str]:
    s = (raw_url or "").lower()
    return sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in s})


def check_url(raw_url: str, blacklist: set[str]) -> tuple[bool, dict]:
    cleaned = (raw_url or "").strip()
    normalized_u = _normalize_url(cleaned)
    normalized_d = _normalize_domain(cleaned)

    in_blacklist = False
    if blacklist and (normalized_u in blacklist or normalized_d in blacklist):
        in_blacklist = True

    hits = keyword_hits(cleaned)
    suspicious = in_blacklist or (len(hits) > 0)

    return suspicious, {
        "cleaned": cleaned,
        "normalized_url": normalized_u,
        "normalized_domain": normalized_d,
        "in_blacklist": in_blacklist,
        "keyword_hits": hits,
    }


def _pick_risk_level(text: str) -> str:
    t = (text or "").replace("「", "").replace("」", "").strip()
    for label in ["高度危險", "有疑慮", "目前無明顯特徵"]:
        if label in t:
            return label
    return "有疑慮"


def analyze_url_with_gemini(
    *,
    raw_url: str,
    details: dict,
    model_name: str,
    api_key: str,
) -> str:
    """根據網址檢查結果，請 Gemini 產生溫暖的說明報告。"""
    cleaned = details.get("cleaned") or raw_url or ""
    normalized_url = details.get("normalized_url") or "（無法正規化）"
    domain = details.get("normalized_domain") or "（無法解析）"
    in_blacklist = details.get("in_blacklist")
    hits = details.get("keyword_hits") or []

    blacklist_text = "是，已命中 165 詐騙黑名單。" if in_blacklist else "否，目前沒有出現在 165 詐騙黑名單中。"
    keyword_text = "、".join(hits) if hits else "無明顯命中的可疑關鍵字。"

    suspicion_flag = "較高" if in_blacklist or hits else "較低（目前沒有明顯異常）"

    system_summary = (
        "以下是系統對使用者輸入網址所做的技術性檢查結果整理：\n"
        f"- 使用者原始輸入網址：{cleaned}\n"
        f"- 正規化後的網址：{normalized_url}\n"
        f"- 判定的網域：{domain}\n"
        f"- 是否命中 165 詐騙黑名單：{blacklist_text}\n"
        f"- 命中的可疑關鍵字：{keyword_text}\n"
        f"- 綜合技術判斷的風險粗略評估：{suspicion_flag}\n"
    )

    user_prompt = (
        system_summary
        + "\n\n請你站在 165 防詐專家的角度，"
        "用溫暖、專業、具同理心且條理分明的繁體中文，"
        "寫一份給民眾看的分析報告，說明：\n"
        "1) 這種網址可能涉及的風險與常見詐騙手法（若看起來較安全，也請說明為何、以及仍需注意的點）。\n"
        "2) 使用者現在應該具體採取的 3-5 個安全步驟（例如不要點開、不要登入、改用官方網址查詢、撥打 165 等）。\n"
        "3) 用簡短的一段話，給予使用者情緒上的安撫與鼓勵，強調願意求證是很重要的一步。\n"
    )

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=model_name,
        system_instruction=GEMINI_URL_SYSTEM_PROMPT,
    )
    resp = model.generate_content(user_prompt)
    return (getattr(resp, "text", None) or "").strip()


def analyze_sms_with_gemini(
    *,
    sms_text: str,
    url_summaries: list[dict],
    context: str,
    model_name: str,
    api_key: str,
) -> tuple[str, str]:
    """根據簡訊內容與黑名單比對結果，請 Gemini 輸出 JSON 分類與分析。"""
    if not url_summaries:
        urls_section = "系統沒有在訊息中偵測到明確的網址或連結。"
    else:
        lines = []
        for info in url_summaries:
            u = info.get("original_url") or info.get("cleaned") or ""
            domain = info.get("normalized_domain") or "（無法解析）"
            in_blacklist = info.get("in_blacklist")
            hits = info.get("keyword_hits") or []
            blacklist_text = "是，已命中 165 詐騙黑名單。" if in_blacklist else "否，目前未出現在 165 詐騙黑名單中。"
            keyword_text = "、".join(hits) if hits else "無特別命中的可疑關鍵字。"
            lines.append(
                f"- 原始網址：{u}\n  - 網域：{domain}\n  - 是否在 165 黑名單：{blacklist_text}\n  - 命中的關鍵字：{keyword_text}"
            )
        urls_section = "\n".join(lines)

    background_summary = (
        "【系統背景比對結果（供你參考）】\n"
        + urls_section
        + "\n\n"
        "提醒：網址有沒有出現在黑名單，只是線索之一；仍需結合訊息內容整體判斷。"
    )

    context_note = context or "（目前沒有額外的官方即時查核資料。）"

    user_prompt = (
        background_summary
        + "\n\n【即時查核取得的官方資料摘要（供你優先參考）】\n"
        + context_note
        + "\n\n【使用者貼上的簡訊 / LINE 訊息原文】\n"
        + sms_text
        + "\n\n請依照系統提示的三分類規則輸出 JSON。"
    )

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=model_name,
        system_instruction=GEMINI_SMS_SYSTEM_PROMPT,
    )
    resp = model.generate_content(user_prompt)
    raw = (getattr(resp, "text", None) or "").strip()

    def _parse_json(text: str) -> dict | None:
        t = (text or "").strip()
        if t.startswith("```"):
            t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
            t = re.sub(r"\s*```$", "", t).strip()
        if not t:
            return None
        try:
            return json.loads(t)
        except Exception:
            m = re.search(r"\{[\s\S]*\}", t)
            if not m:
                return None
            try:
                return json.loads(m.group(0))
            except Exception:
                return None

    parsed = _parse_json(raw) or {}
    category = (parsed.get("category") or "").strip()
    analysis = (parsed.get("analysis") or "").strip()

    allowed = {"🔴 詐騙高風險", "🟡 健康謠言/假新聞", "🔵 帶風向/情緒煽動疑慮", "🟢 安全與日常資訊"}
    if category not in allowed:
        category = "🟡 健康謠言/假新聞" if raw else "🟡 健康謠言/假新聞"

    if not analysis:
        analysis = raw or "（AI 沒有回傳可解析的 JSON 內容，建議稍後再試一次。）"

    return category, analysis


def analyze_image_with_gemini(
    *,
    image_file,
    model_name: str,
    api_key: str,
    retrieval_note: str | None = None,
) -> tuple[str, str]:
    img_bytes = image_file.getvalue()
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    img.thumbnail((1280, 1280))

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=model_name,
        system_instruction=GEMINI_SYSTEM_PROMPT,
    )

    base_prompt = (
        "請分析這張圖片的內容，判斷是否與詐騙、健康謠言、帶風向/情緒煽動或一般安全日常資訊有關。\n"
        "請依照系統提示的四種分類標籤輸出 JSON。"
    )

    if retrieval_note:
        user_prompt = (
            base_prompt
            + "\n\n【系統背景檢索結果（供你參考）】\n"
            + retrieval_note
        )
    else:
        user_prompt = base_prompt

    resp = model.generate_content([user_prompt, img])
    raw = (getattr(resp, "text", None) or "").strip()

    def _parse_json(text: str) -> dict | None:
        t = (text or "").strip()
        if t.startswith("```"):
            t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
            t = re.sub(r"\s*```$", "", t).strip()
        if not t:
            return None
        try:
            return json.loads(t)
        except Exception:
            m = re.search(r"\{[\s\S]*\}", t)
            if not m:
                return None
            try:
                return json.loads(m.group(0))
            except Exception:
                return None

    parsed = _parse_json(raw) or {}
    category = (parsed.get("category") or "").strip()
    analysis = (parsed.get("analysis") or "").strip()

    allowed = {"🔴 詐騙高風險", "🟡 健康謠言/假新聞", "🔵 帶風向/情緒煽動疑慮", "🟢 安全與日常資訊"}
    if category not in allowed:
        category = "🟡 健康謠言/假新聞"

    if not analysis:
        analysis = raw or "（AI 沒有回傳可解析的 JSON 內容，建議稍後再試一次。）"

    return category, analysis


def analyze_audio_with_gemini(
    *,
    audio_file,
    context: str,
    model_name: str,
    api_key: str,
) -> tuple[str, str]:
    """使用 Gemini 針對語音進行三分類並回傳 (category, analysis)。"""
    audio_bytes = audio_file.getvalue()
    if not audio_bytes:
        return "🟡 健康謠言/假新聞", "（沒有收到有效的語音資料。）"

    mime_type = getattr(audio_file, "type", None) or "audio/wav"

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=model_name,
        system_instruction=GEMINI_AUDIO_SYSTEM_PROMPT,
    )

    audio_part = {
        "mime_type": mime_type,
        "data": audio_bytes,
    }

    context_note = context or "（目前沒有額外的官方即時查核資料。）"
    user_prompt = (
        "【即時查核取得的官方資料摘要（供你優先參考）】\n"
        + context_note
        + "\n\n請依照系統提示的三分類規則輸出 JSON。"
    )

    resp = model.generate_content([audio_part, user_prompt])
    raw = (getattr(resp, "text", None) or "").strip()

    def _parse_json(text: str) -> dict | None:
        t = (text or "").strip()
        if t.startswith("```"):
            t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
            t = re.sub(r"\s*```$", "", t).strip()
        if not t:
            return None
        try:
            return json.loads(t)
        except Exception:
            m = re.search(r"\{[\s\S]*\}", t)
            if not m:
                return None
            try:
                return json.loads(m.group(0))
            except Exception:
                return None

    parsed = _parse_json(raw) or {}
    category = (parsed.get("category") or "").strip()
    analysis = (parsed.get("analysis") or "").strip()

    allowed = {"🔴 詐騙高風險", "🟡 健康謠言/假新聞", "🔵 帶風向/情緒煽動疑慮", "🟢 安全與日常資訊"}
    if category not in allowed:
        category = "🟡 健康謠言/假新聞"

    if not analysis:
        analysis = raw or "（AI 沒有回傳可解析的 JSON 內容，建議稍後再試一次。）"

    return category, analysis


# =========================
# UI
# =========================
st.set_page_config(page_title="防詐騙網址檢查", page_icon="🛡️", layout="wide")

st.markdown("## 🛡️ 防詐騙網址檢查小工具")
st.write("請選擇要檢查的類型：**網址** 或 **圖片/截圖**。")

load_dotenv()
gemini_api_key = os.getenv(GEMINI_API_ENV_VAR, "").strip()

with st.sidebar:
    st.markdown("### ⚙️ 設定")
    st.caption("你可以先不設定黑名單來源；網址檢查仍可用關鍵字做初步檢查。")
    source_url = st.text_input("🧾 165 黑名單資料網址（JSON/CSV）", value=BLACKLIST_SOURCE_URL, placeholder="貼上資料開放平台 API 或可下載連結")

    col_a, col_b = st.columns([1, 1])
    with col_a:
        refresh = st.button("🔄 重新載入黑名單")
    with col_b:
        show_details = st.checkbox("顯示比對細節", value=True)

    if refresh:
        st.cache_data.clear()

    st.divider()
    st.markdown("### 🤖 圖片分析（Gemini）")
    gemini_model = st.selectbox(
        "模型",
        options=["gemini-2.5-flash", "gemini-2.5-pro"],
        index=0,
    )
    if gemini_api_key:
        st.success("✅ 已讀取 Gemini API Key（來自 .env / 環境變數）")
    else:
        st.warning("⚠️ 尚未讀到 Gemini API Key（請建立 .env 並設定 GEMINI_API_KEY）")

blacklist, blacklist_status = load_external_blacklist(source_url)

tab_url, tab_image, tab_sms, tab_audio = st.tabs(
    ["🌐 網址檢查", "🖼️ 圖片/截圖檢查", "📝 簡訊文字分析", "🎤 語音求助"]
)

with tab_url:
    top_left, top_right = st.columns([3, 2], vertical_alignment="top")

    with top_left:
        st.markdown("### 🔎 輸入網址")
        url = st.text_input(
            "請貼上要檢查的網址：",
            placeholder="例如：https://example.com/path?ref=free-money",
            label_visibility="visible",
        )

        action_left, action_right = st.columns([1, 3])
        with action_left:
            run_check = st.button("🚦 開始檢查", use_container_width=True)
        with action_right:
            st.caption(blacklist_status)

    with top_right:
        st.markdown("### 📌 快速提示")
        st.info("看到要求你**立刻登入/驗證/更新帳單**、或宣稱**免費送錢/空投/中獎**的連結，請特別小心。")

    st.divider()

    if run_check:
        if not (url or "").strip():
            st.warning("⚠️ 請先輸入一個網址再按『開始檢查』。")
        else:
            suspicious, details = check_url(url, blacklist)

            if suspicious:
                st.error("⚠️ 警告：可能是詐騙網址！")
            else:
                st.success("✅ 此網址目前看起來安全（依黑名單與關鍵字初步判斷）。")

            if show_details:
                cols = st.columns(3)
                cols[0].metric("🧾 黑名單命中", "是" if details["in_blacklist"] else "否")
                cols[1].metric("🧩 關鍵字命中數", str(len(details["keyword_hits"])))
                cols[2].metric("🌐 網域", details["normalized_domain"] or "（無法解析）")

                if details["keyword_hits"]:
                    st.write("**命中的可疑特徵：** " + "、".join(details["keyword_hits"]))

            # 讓 Gemini 針對上述技術結果，產生溫暖且具同理心的分析報告
            if gemini_api_key:
                with st.spinner("🧠 Gemini 正在撰寫網址分析報告..."):
                    try:
                        url_report = analyze_url_with_gemini(
                            raw_url=url,
                            details=details,
                            model_name=gemini_model,
                            api_key=gemini_api_key,
                        )
                    except Exception as e:
                        url_report = ""
                        st.warning(f"AI 報告生成失敗：{e}")

                if url_report:
                    st.markdown("### 🤖 AI 防詐騙分析報告")
                    if suspicious:
                        st.error("🚨 綜合評估：此網址具有明顯風險，請務必提高警覺。")
                    else:
                        st.success("💡 綜合評估：目前沒有明顯高風險特徵，但仍建議保持基本警覺。")
                    st.markdown(url_report)
            else:
                st.caption("（尚未設定 Gemini API Key，因此僅顯示系統比對結果。）")

with tab_image:
    st.markdown("### 🖼️ 上傳圖片或截圖")
    uploaded_file = st.file_uploader(
        "請上傳要檢查的圖片（例如簡訊截圖、社群貼文截圖）：",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=False,
    )

    if uploaded_file is not None:
        # 如果使用者重新上傳不同的圖片，清除舊的分析結果
        file_signature = f"{getattr(uploaded_file, 'name', '')}:{getattr(uploaded_file, 'size', '')}"
        prev_signature = st.session_state.get("last_image_file_sig")
        if file_signature != prev_signature:
            st.session_state["last_image_file_sig"] = file_signature
            st.session_state["last_image_result"] = None

        st.image(uploaded_file, caption="上傳的圖片預覽", width=400)
        url_in_image = st.text_input(
            "（選填）圖片中出現的網址或連結：",
            placeholder="例如：https://bank.example.com/login",
        )
        action_l, action_r = st.columns([1, 2], vertical_alignment="center")
        with action_l:
            run_img = st.button("🔍 分析圖片內容", use_container_width=True)
        with action_r:
            st.caption("提示：分析會把圖片內容送到 Gemini 進行判讀。")

        if run_img:
            if not gemini_api_key:
                st.error("❌ 找不到 Gemini API Key。請先建立 `.env` 並設定 `GEMINI_API_KEY=你的金鑰`，再重新啟動 Streamlit。")
            else:
                retrieval_note = "未提供明確網址，僅依圖片內容進行判斷。"
                url_in_image_clean = (url_in_image or "").strip()
                if url_in_image_clean:
                    _, url_details = check_url(url_in_image_clean, blacklist)
                    if url_details["in_blacklist"]:
                        retrieval_note = (
                            "此網址已列入警政署 165 詐騙黑名單"
                            f"（網域：{url_details['normalized_domain'] or '未知'}）。"
                        )
                    else:
                        retrieval_note = (
                            "此網址目前未出現在警政署 165 詐騙黑名單中"
                            f"（網域：{url_details['normalized_domain'] or '未知'}），"
                            "但仍可能存在風險，請結合圖片內容與其他線索謹慎評估。"
                        )

                with st.spinner("🧠 Gemini 分析中，請稍候..."):
                    try:
                        img_category, img_analysis = analyze_image_with_gemini(
                            image_file=uploaded_file,
                            model_name=gemini_model,
                            api_key=gemini_api_key,
                            retrieval_note=retrieval_note,
                        )
                        st.session_state["last_image_result"] = (img_category, img_analysis)
                    except Exception as e:
                        st.session_state["last_image_result"] = None
                        st.error(f"分析失敗：{e}")

        result = st.session_state.get("last_image_result")
        if result:
            img_category, img_analysis = result

            st.markdown("### 📋 AI 圖片分析報告")
            if img_category == "🔴 詐騙高風險":
                st.error(f"🚨 {img_category}\n\n{img_analysis}")
            elif img_category == "🟡 健康謠言/假新聞":
                st.warning(f"⚠️ {img_category}\n\n{img_analysis}")
            elif img_category == "🔵 帶風向/情緒煽動疑慮":
                st.info(f"ℹ️ {img_category}\n\n{img_analysis}")
            else:
                st.success(f"✅ {img_category}\n\n{img_analysis}")
    else:
        st.caption("提示：你可以先上傳銀行簡訊截圖、LINE 對話截圖等，這裡會用 Gemini 做初步詐騙判讀。")

with tab_sms:
    st.markdown("### 📝 簡訊文字分析")
    st.markdown("### 請貼上可疑的簡訊或 LINE 訊息內容")

    sms_text = st.text_area(
        label="",
        placeholder="例如：\n【重要通知】您帳戶異常，請立即登入 https://example.com/login 更新資料，否則將凍結帳戶。",
        height=180,
    )

    sms_analyze = st.button("📨 分析這則訊息", use_container_width=True)

    if sms_analyze:
        if not (sms_text or "").strip():
            st.warning("⚠️ 請先貼上一段簡訊或 LINE 訊息，再按『分析這則訊息』。")
        elif not gemini_api_key:
            st.error("❌ 找不到 Gemini API Key。請先在 `.env` 中設定 `GEMINI_API_KEY`，再重新啟動程式。")
        else:
            urls_in_sms = extract_urls_from_text(sms_text)

            url_summaries: list[dict] = []
            for u in urls_in_sms:
                _, d = check_url(u, blacklist)
                d_with_original = dict(d)
                d_with_original["original_url"] = u
                url_summaries.append(d_with_original)

            st.info("🔍 正在連線至衛福部與警政署資料庫進行即時查核...")
            fact_context = live_fact_check(sms_text)

            with st.spinner("🧠 Gemini 正在閱讀這則訊息並進行防詐分析..."):
                try:
                    sms_category, sms_analysis = analyze_sms_with_gemini(
                        sms_text=sms_text,
                        url_summaries=url_summaries,
                        context=fact_context,
                        model_name=gemini_model,
                        api_key=gemini_api_key,
                    )
                except Exception as e:
                    sms_category, sms_analysis = "🟡 健康謠言/假新聞", ""
                    st.error(f"分析失敗：{e}")

            # 依 category 用不同顏色與大表情符號呈現（長者友善）
            if sms_category == "🔴 詐騙高風險":
                st.error(f"🚨 {sms_category}\n\n{sms_analysis}")
            elif sms_category == "🔵 帶風向/情緒煽動疑慮":
                st.info(f"ℹ️ {sms_category}\n\n{sms_analysis}")
            elif sms_category == "🟡 健康謠言/假新聞":
                st.warning(f"⚠️ {sms_category}\n\n{sms_analysis}")
            else:
                st.success(f"✅ {sms_category}\n\n{sms_analysis}")

            with st.expander("⚙️ 系統檢測技術摘要 (供家屬參考)"):
                st.write(f"**AI 判定標籤類別：** {sms_category}")

                if urls_in_sms:
                    st.write("**原始訊息中偵測到的網址：**")
                    for info in url_summaries:
                        u = info.get("original_url") or ""
                        st.write(f"- `{u}`")
                else:
                    st.write("**原始訊息中未偵測到明顯的網址。**")

                st.write("**165 黑名單與關鍵字比對結果：**")
                if urls_in_sms:
                    for info in url_summaries:
                        u = info.get("original_url") or ""
                        domain = info.get("normalized_domain") or "（無法解析）"
                        in_blacklist = info.get("in_blacklist")
                        hits = info.get("keyword_hits") or []
                        st.write(f"- 網址：`{u}`")
                        st.write(f"  - 網域：`{domain}`")
                        st.write(f"  - 是否在 165 黑名單：{'是' if in_blacklist else '否'}")
                        if hits:
                            st.write(f"  - 命中的可疑關鍵字：{'、'.join(hits)}")
                        st.write("---")
                else:
                    st.write("目前沒有網址可供 165 黑名單比對。")

with tab_audio:
    st.markdown("### 🎤 語音求助")
    st.markdown(
        "### 👉 步驟一：點擊下方麥克風開始錄音。\n"
        "### 👉 步驟二：錄音完成後，點擊下方的【開始分析語音】按鈕。"
    )

    audio_data = st.audio_input("請點擊麥克風，說出您的問題，或播放可疑的語音訊息給我聽：")
    run_audio = st.button("開始分析語音", use_container_width=True)

    if run_audio:
        if audio_data is None or not audio_data.getvalue():
            st.warning("⚠️ 系統沒有收到聲音喔！請確認您有按下麥克風並說話。")
        elif not gemini_api_key:
            st.warning("⚠️ 尚未設定 Gemini API Key，無法進行語音分析。請先在 `.env` 中設定 `GEMINI_API_KEY`。")
        else:
            st.info("🔍 正在連線至衛福部與警政署資料庫進行即時查核...")
            # 目前沒有語音文字內容可用來當查詢，先用通用關鍵字做基本查核
            fact_context = live_fact_check("語音 詐騙 闢謠")

            with st.spinner("🧠 正在仔細聆聽並分析語音內容，請稍候..."):
                try:
                    audio_category, audio_analysis = analyze_audio_with_gemini(
                        audio_file=audio_data,
                        context=fact_context,
                        model_name=gemini_model,
                        api_key=gemini_api_key,
                    )
                except Exception as e:
                    audio_category, audio_analysis = "🟡 健康謠言/假新聞", ""
                    st.warning(f"語音分析失敗，請稍後再試：{e}")

            if audio_analysis:
                if audio_category == "🔴 詐騙高風險":
                    st.error(f"🚨 {audio_category}\n\n{audio_analysis}")
                elif audio_category == "🔵 帶風向/情緒煽動疑慮":
                    st.info(f"ℹ️ {audio_category}\n\n{audio_analysis}")
                elif audio_category == "🟡 健康謠言/假新聞":
                    st.warning(f"⚠️ {audio_category}\n\n{audio_analysis}")
                else:
                    st.success(f"✅ {audio_category}\n\n{audio_analysis}")
    else:
        st.caption("提示：請依照步驟錄音，錄完後再按【開始分析語音】進行判斷。")

with st.expander("🧠 這個工具是如何運作的？（點我展開）"):
    st.markdown(
        """
**網址檢查的判斷流程（由強到弱）**
- **165 外部黑名單比對**：如果你在側邊欄填入「165 反詐騙假網站」的公開資料（JSON/CSV），工具會自動下載並解析，並把網址/網域整理成一份黑名單。  
  - 只要你輸入的網址（或網域）出現在黑名單中，就會**直接判定為詐騙**。
- **關鍵字特徵比對**：若黑名單沒有命中，才會檢查網址字串是否包含常見詐騙特徵（例如可疑頂級網域、釣魚字串、拼字偽裝等）。

**圖片/截圖檢查（規劃中）**
- 上傳圖片後，會把圖片送到 Gemini 視覺模型，檢查常見詐騙話術、可疑網址、冒充官方等特徵，並輸出結論與建議。

**注意**
- 這是教學版工具：它做的是「初步篩查」，不能保證 100% 安全。遇到可疑連結或圖片仍建議用多來源查證、不要輸入個資/OTP。
        """
    )

st.caption("📎 教學提醒：此工具只做初步判斷；請保持警覺、不要隨便輸入個資或驗證碼。"
)