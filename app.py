from __future__ import annotations

import io
import os
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv
from PIL import Image

import google.generativeai as genai
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# =========================
# 1) 政府/外部黑名單來源（請在這裡填入）
# =========================
#
# 你未來只要把這個變數改成「165 反詐騙假網站」公開資料的 JSON/CSV 連結即可。
# 例如：資料開放平台的 API 端點、或直接可下載的 CSV 檔。
# 目前先放一個標準 CSV 連結佔位符，之後你可以自行改成 data.gov.tw 上 165 黑名單的真實 CSV 下載網址。
BLACKLIST_SOURCE_URL = "https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/29E8E643-88ED-4952-B21E-BD42A3B7108C/resource/C0FCAC14-F724-406E-9061-119D2C82327B/download"

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
    "你是一位台灣警政署 165 級別的防詐騙專家。請掃描這張圖片，判斷是否包含詐騙特徵"
    "（例如：不合理的獲利保證、假冒的官方機構、要求提供密碼或匯款、可疑的網址、或是常見的詐騙話術等）。"
    "請用繁體中文給出簡潔、條理分明的分析，並給出『高度危險』、『有疑慮』或『目前無明顯特徵』的結論。"
)

GEMINI_URL_SYSTEM_PROMPT = (
    "你是一位台灣警政署 165 級別的防詐騙專家。你會收到系統整理好的網址檢查情報，"
    "其中包含是否命中 165 詐騙黑名單、命中的可疑關鍵字、網域與其他技術細節。"
    "請先充分理解這些背景情報，再用溫暖、專業、具同理心且條理分明的繁體中文，"
    "寫給一般民眾看的防詐騙分析報告；若風險較高要明確提醒與給建議，若目前看起來安全也要提醒保持警覺。"
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


def _extract_urls_from_csv_text(csv_text: str) -> list[str]:
    df = pd.read_csv(io.StringIO(csv_text))
    lower_to_col = {str(c).strip().lower(): c for c in df.columns}

    for key in POSSIBLE_URL_FIELDS:
        c = lower_to_col.get(key.lower())
        if c is not None:
            series = df[c].dropna().astype(str)
            return series.tolist()

    all_vals = (
        df.astype(str)
        .replace("nan", "")
        .values
        .ravel()
        .tolist()
    )
    return [v for v in all_vals if v and ("://" in v or "." in v)]


@st.cache_data(ttl=3600, show_spinner=False)
def load_external_blacklist(source_url: str) -> tuple[set[str], str]:
    if not source_url.strip():
        return set(), "尚未設定黑名單來源網址（目前只用關鍵字特徵比對）。"

    try:
        # 忽略 SSL 憑證驗證，以避免部分政府站台憑證設定問題導致錯誤
        resp = requests.get(source_url, timeout=15, verify=False)
        resp.raise_for_status()
    except Exception as e:
        return set(), f"黑名單下載失敗：{e}"

    content_type = (resp.headers.get("content-type") or "").lower()
    text = resp.text

    candidates: list[str] = []
    if "application/json" in content_type or source_url.lower().endswith(".json"):
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


def analyze_image_with_gemini(
    *,
    image_file,
    model_name: str,
    api_key: str,
    retrieval_note: str | None = None,
) -> dict:
    img_bytes = image_file.getvalue()
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    img.thumbnail((1280, 1280))

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name=model_name,
        system_instruction=GEMINI_SYSTEM_PROMPT,
    )

    base_prompt = (
        "請分析這張圖片是否有詐騙特徵，並用繁體中文輸出：\n"
        "1) 結論：三選一（高度危險／有疑慮／目前無明顯特徵）\n"
        "2) 主要理由：條列 3-8 點\n"
        "3) 圖中可疑資訊（若有）：可疑網址/網域、電話、LINE ID、要求匯款方式等\n"
        "4) 建議下一步：給 3 點具體建議（例如不要點連結、改用官方管道查證、撥打 165 等）\n"
    )

    if retrieval_note:
        user_prompt = (
            base_prompt
            + "\n\n系統背景檢索結果："
            + retrieval_note
            + "\n請結合上述背景情報與圖片內容，一併納入整體風險評估中。"
        )
    else:
        user_prompt = base_prompt

    resp = model.generate_content([user_prompt, img])
    report_text = (getattr(resp, "text", None) or "").strip()

    risk = _pick_risk_level(report_text)
    return {
        "risk": risk,
        "report": report_text or "（模型未回傳可顯示的文字內容）",
        "model": model_name,
    }


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

tab_url, tab_image = st.tabs(["🌐 網址檢查", "🖼️ 圖片/截圖檢查"])

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
                        result = analyze_image_with_gemini(
                            image_file=uploaded_file,
                            model_name=gemini_model,
                            api_key=gemini_api_key,
                            retrieval_note=retrieval_note,
                        )
                        st.session_state["last_image_result"] = result
                    except Exception as e:
                        st.session_state["last_image_result"] = None
                        st.error(f"分析失敗：{e}")

        result = st.session_state.get("last_image_result")
        if result:
            risk = result.get("risk", "有疑慮")
            report = result.get("report", "")

            st.markdown("### 📋 AI 分析報告")
            if risk == "高度危險":
                st.error(f"🚨 結論：**{risk}**")
            elif risk == "目前無明顯特徵":
                st.success(f"✅ 結論：**{risk}**")
            else:
                st.warning(f"⚠️ 結論：**{risk}**")

            st.markdown(report)
            st.caption(f"模型：`{result.get('model', gemini_model)}`")
    else:
        st.caption("提示：你可以先上傳銀行簡訊截圖、LINE 對話截圖等，這裡會用 Gemini 做初步詐騙判讀。")

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